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
CREATE_RUN_URL = BASE_TFE_API_URL + '/runs'
CONFIG_PATTERN = re.compile('^config\.[0-9]*\.name')
API_REQUEST_HEADERS = {
  'Authorization': 'Bearer {}'.format(environ['API_TOKEN']),
  'Content-Type': 'application/vnd.api+json'
}
WORKSPACE_DEPENDENCIES_TABLE = boto3.resource('dynamodb').Table(environ['WORKSPACE_DEPENDENCIES_TABLE'])
WORKSPACE_ID_NAME = 'workspace_id'
REMOTE_WORKSPACE_IDS_NAME = 'remote_workspace_ids'


logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
  body = event['body']
  if 'NOTIFICATION_TOKEN' in environ:
    if hmac.new(environ['NOTIFICATION_TOKEN'], body, sha512).hexdigest() != event['headers'].get('X-TFE-Notification-Signature'):
      logger.warning('Invalid token: {}'.format(event['headers'].get('X-TFE-Notification-Signature')))
      return {
        'statusCode': 400,
        'body': 'Invalid or missing X-TFE-Notification-Signature header'
      }
  notification_body = json.loads(body)
  for notification in notification_body['notifications']:
    if notification['trigger'] == 'run:completed':
      workspace_id = notification_body[WORKSPACE_ID_NAME]
      logger.info('Run completed notification received for {}'.format(workspace_id))
      remote_workspace_ids = get_remote_workspace_ids(workspace_id)
      register_workspace_dependencies(workspace_id, remote_workspace_ids)
      run_dependent_workspaces(workspace_id, context.function_name)
      break
  return {
    'statusCode': 204
  }

def get_remote_workspace_ids(workspace_id):
  logger.info('Getting wokspace info for {}'.format(workspace_id))
  response = requests.get(
    CURRENT_STATE_VERSION_API_URL.format(workspace_id), 
    headers=API_REQUEST_HEADERS
  )
  response.raise_for_status()
  current_state_version = response.json()
  logger.info('Getting state for workspace {}'.format(workspace_id))
  response = requests.get(current_state_version['data']['attributes']['hosted-state-download-url'])
  response.raise_for_status()
  state = response.json()
  remote_workspace_ids = []
  for module in state['modules']:
    for key, value in module['resources'].items():
      if key.startswith('data.terraform_remote_state.') and \
        value['type'] == 'terraform_remote_state' and \
          value['primary']['attributes']['backend'] == 'atlas':
        for key2, value2 in value['primary']['attributes']:
          if CONFIG_PATTERN.match(key2):
            elements = value2.split('/')
            response = requests.get(
              SHOW_WORKSPACE_API_URL.format(elements[0], elements[1]), 
              headers=API_REQUEST_HEADERS
            )
            response.raise_for_status()
            remote_workspace_ids.append(response['data']['id'])
            break
  return remote_workspace_ids


def register_workspace_dependencies(workspace_id, remote_workspace_ids):
  logger.info(
    'Registering remote workspace ids {} for workspace {}'.format(
      remote_workspace_ids, 
      workspace_id
    )
  )
  WORKSPACE_DEPENDENCIES_TABLE.put_item(
    Item={
      WORKSPACE_ID_NAME: workspace_id,
      REMOTE_WORKSPACE_IDS_NAME: set(remote_workspace_ids),
    }
  )

def run_dependent_workspaces(workspace_id, function_name, exclusive_start_key=None):
  logger.info('Scanning for dependent workspaces for workspace {}'.format(workspace_id))
  response = WORKSPACE_DEPENDENCIES_TABLE.scan(
    ExclusiveStartKey=exclusive_start_key,
    FilterExpression=Attr(REMOTE_WORKSPACE_IDS_NAME).contains(workspace_id),
    ConsistentRead=True,
  )
  if 'Items' in response:
    for item in response['Items']:
      run_dependent_workspace(item[WORKSPACE_ID_NAME], function_name)
  if 'LastEvaluatedKey' in response:
    run_dependent_workspaces(workspace_id, exclusive_start_key=response['LastEvaluatedKey'])

def run_dependent_workspace(workspace_id, function_name):
  logger.info('Creating run for workspace {}'.format(workspace_id))
  response = requests.post(
    CREATE_RUN_URL, 
    headers=API_REQUEST_HEADERS,
    data={
      'data': {
        'attributes': {
          'message': 'Queued automatically from {}'.format(function_name),
        },
        'relationships': {
          'workspace': {
            'data': {
              'type': 'workspaces',
              'id': workspace_id,
            },
          },
        },
      },
    }
  )
  if response.status_code != requests.codes.created:
    logger.warning(
      'Failed to create run for workspace {}, code {}, message {}'.format(
        workspace_id, response.status_code, json.dumps(response.json)
      )
    )
