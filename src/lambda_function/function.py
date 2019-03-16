import boto3
import hmac
import json
import logging.config
import re
import requests

from boto3.dynamodb.conditions import Attr
from hashlib import sha512
from os import environ

BASE_TFE_API_URL = 'https://app.terraform.io/api/v2'
CURRENT_STATE_VERSION_API_URL = BASE_TFE_API_URL + '/workspaces/{}/current-state-version'
SHOW_WORKSPACE_API_URL = BASE_TFE_API_URL + '/organizations/{}/workspaces/{}'
CREATE_RUN_API_URL = BASE_TFE_API_URL + '/runs'
CONFIG_PATTERN = re.compile('^config\.[0-9]*\.name')
API_REQUEST_HEADERS = {
  'Authorization': 'Bearer {}'.format(environ['API_TOKEN']),
  'Content-Type': 'application/vnd.api+json'
}
API_RESPONSE_HEADERS = {
  'Content-Type': 'text/plain'
}
WORKSPACE_DEPENDENCIES_TABLE = boto3.resource('dynamodb').Table(environ['WORKSPACE_DEPENDENCIES_TABLE'])
ORGANIZATION_FIELD = 'organization_name'
WORKSPACE_FIELD = 'workspace_name'
WORKSPACE_ID_FIELD = 'workspace_id'
REMOTE_WORKSPACES_FIELD = 'remote_workspaces'


logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
  body = event['body']
  if 'NOTIFICATION_TOKEN' in environ or 'X-Tfe-Notification-Signature' in event['headers']:
    if not 'NOTIFICATION_TOKEN' in environ:
      logger.error('Missing NOTIFICATION_TOKEN in environment')
      return {
        'statusCode': requests.codes.server_error,
        'headers': API_RESPONSE_HEADERS,
        'body': 'Missing NOTIFICATION_TOKEN in environment',
      }
    elif not 'X-Tfe-Notification-Signature' in event['headers']:
      logger.warning('Missing X-Tfe-Notification-Signature header')
      return {
        'statusCode': requests.codes.bad_request,
        'headers': API_RESPONSE_HEADERS,
        'body': 'Missing X-Tfe-Notification-Signature header',
      }
    elif hmac.new(str.encode(environ['NOTIFICATION_TOKEN']), str.encode(body), sha512).hexdigest() != event['headers'].get('X-Tfe-Notification-Signature'):
      logger.warning('Invalid  X-Tfe-Notification-Signature header: {}'.format(event['headers'].get('X-Tfe-Notification-Signature')))
      return {
        'statusCode': requests.codes.bad_request,
        'headers': API_RESPONSE_HEADERS,
        'body': 'Invalid X-Tfe-Notification-Signature header {}'.format(event['headers'].get('X-Tfe-Notification-Signature')),
      }
  notification_body = json.loads(body)
  for notification in notification_body['notifications']:
    if notification['trigger'] == 'run:completed':
      organization = notification_body[ORGANIZATION_FIELD]
      workspace = notification_body[WORKSPACE_FIELD]
      logger.info('Run completed notification received for {}/{}'.format(organization, workspace))
      remote_workspaces = _get_remote_workspaces(notification_body[WORKSPACE_ID_FIELD])
      _register_workspace_dependencies(organization, workspace, remote_workspaces)
      _run_dependent_workspaces(organization, workspace)
      return {
        'statusCode': requests.codes.accepted,
        'headers': API_RESPONSE_HEADERS,
        'body': 'Registered and running dependencies for {}/{}'.format(organization, workspace),
      }
  return {
    'statusCode': requests.codes.ok,
  }

def _get_remote_workspaces(workspace_id):
  logger.info('Getting current state version for {}'.format(workspace_id))
  response = requests.get(
    CURRENT_STATE_VERSION_API_URL.format(workspace_id), 
    headers=API_REQUEST_HEADERS
  )
  response.raise_for_status()
  current_state_version = response.json()
  logger.info('Getting current state for workspace {}'.format(workspace_id))
  response = requests.get(current_state_version['data']['attributes']['hosted-state-download-url'])
  response.raise_for_status()
  state = response.json()
  remote_workspaces = set()
  for module in state['modules']:
    for key, value in module['resources'].items():
      if key.startswith('data.terraform_remote_state.') and \
        value['type'] == 'terraform_remote_state' and \
          value['primary']['attributes']['backend'] == 'atlas':
        for key2, value2 in value['primary']['attributes'].items():
          if CONFIG_PATTERN.match(key2):
            remote_workspaces.add(value2)
            break
  return remote_workspaces


def _register_workspace_dependencies(organization, workspace, remote_workspaces):
  logger.info(
    'Registering remote workspaces {} for workspace {}/{}'.format(
      remote_workspaces if remote_workspaces else None, 
      organization,
      workspace
    )
  )
  if remote_workspaces:
    WORKSPACE_DEPENDENCIES_TABLE.put_item(
      Item={
        ORGANIZATION_FIELD: organization,
        WORKSPACE_FIELD: workspace,
        REMOTE_WORKSPACES_FIELD: remote_workspaces,
      }
    )
  else:
    WORKSPACE_DEPENDENCIES_TABLE.put_item(
      Item={
        ORGANIZATION_FIELD: organization,
        WORKSPACE_FIELD: workspace,
      }
    )

def _run_dependent_workspaces(organization, workspace, exclusive_start_key=None):
  logger.info('Scanning for dependent workspaces for workspace {}/{}'.format(organization, workspace))
  if exclusive_start_key:
    response = WORKSPACE_DEPENDENCIES_TABLE.scan(
      ExclusiveStartKey=exclusive_start_key,
      ProjectionExpression='{},{}'.format(ORGANIZATION_FIELD, WORKSPACE_FIELD),
      FilterExpression=Attr(REMOTE_WORKSPACES_FIELD).contains('{}/{}'.format(organization, workspace)),
      ConsistentRead=True,
    )
  else:
    response = WORKSPACE_DEPENDENCIES_TABLE.scan(
      ProjectionExpression='{},{}'.format(ORGANIZATION_FIELD, WORKSPACE_FIELD),
      FilterExpression=Attr(REMOTE_WORKSPACES_FIELD).contains('{}/{}'.format(organization, workspace)),
      ConsistentRead=True,
    )
  if 'Items' in response:
    for item in response['Items']:
      _run_dependent_workspace(item[ORGANIZATION_FIELD], item[WORKSPACE_FIELD], '{}/{}'.format(organization, workspace))
  if 'LastEvaluatedKey' in response:
    _run_dependent_workspaces(organization, workspace, exclusive_start_key=response['LastEvaluatedKey'])

def _run_dependent_workspace(organization, workspace, originating_workspace):
  workspace_response = requests.get(
    SHOW_WORKSPACE_API_URL.format(organization, workspace),
    headers=API_REQUEST_HEADERS
  )
  if workspace_response.status_code == requests.codes.ok:
    logger.info('Creating run for workspace {}/{}'.format(organization, workspace))
    run_response = requests.post(
      CREATE_RUN_API_URL, 
      headers=API_REQUEST_HEADERS,
      data=json.dumps(
        {
          'data': {
            'attributes': {
              'message': 'Queued automatically from {}'.format(originating_workspace),
            },
            'type': 'runs',
            'relationships': {
              'workspace': {
                'data': {
                  'type': 'workspaces',
                  'id': workspace_response.json()['data']['id'],
                },
              },
            },
          },
        }
      )
    )
    if run_response.status_code != requests.codes.created:
      logger.warning(
        'Failed to create run for workspace {}/{}, code {}, message {}'.format(
          organization, workspace, run_response.status_code, json.dumps(run_response.json())
        )
      )
  elif workspace_response.status_code == requests.codes.not_found:
    logger.info('Workspace {}/{} does not exist, deleteing'.format(organization, workspace))
    WORKSPACE_DEPENDENCIES_TABLE.delete_item(
      Key={
        ORGANIZATION_FIELD: organization,
        WORKSPACE_FIELD: workspace
      }
    )
  else:
    logger.warning(
      'Failed to get Workspace ID for workspace {}/{}, code {}, message {}'.format(
          organization, workspace, workspace_response.status_code, workspace_response.text
      )
    )
