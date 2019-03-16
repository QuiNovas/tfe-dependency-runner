============================
tfe-dependency-runner
============================

.. _APL2: http://www.apache.org/licenses/LICENSE-2.0.txt
.. _Terraform Enterprise: https://www.terraform.io/docs/enterprise/index.html
.. _user token: https://www.terraform.io/docs/enterprise/users-teams-organizations/users.html#api-tokens
.. _team token: https://www.terraform.io/docs/enterprise/users-teams-organizations/service-accounts.html#team-service-accounts
.. _organization token: https://www.terraform.io/docs/enterprise/users-teams-organizations/service-accounts.html#organization-service-accounts
.. _notifications: https://www.terraform.io/docs/enterprise/api/notification-configurations.html

Listens for `Terraform Enterprise`_ (TFE) build `notifications`_
and initiates dependent workspace runs

This function is designed to be attached to an AWS API Gateway web-hook
receiver whose endpoint is registered for workspace run `notifications`_.

It will only execute on ``run:completed`` `notifications`_. When one of these
is received:

#. We get the current state version
#. We retrieve the actual state file
#. We parse the state file, looking for any declared *terraform_remote_state* objects
#. We retrieve the *organization/workspace* for any *terraform_remote_state* that are of type *atlas*
#. We register the found dependencies for the current *workspace*
#. If there are any TFE workspaces that depend upon the notified workspace, we create runs
#. If we are not longer able to get the *workspace_id* for an *organization/workspace*, we remove the *organization/workspace* from the dependencies table

Required AWS Resources
----------------------
API Gateway
  Provides Lambda Proxy events to this function
DynamoDB Table
  Where the dependency map is stored. Must have a partition key called
  ``orgainzation`` and a range key called ``workspace``

Required Permissions
--------------------
- dynamodb:DeleteItem
- dynamodb:PutItem
- dynamodb:Scan

Environment Variables
---------------------
**API_TOKEN** (Required)
  The TFE API Token. It must be either a `user token`_ or a `team token`_. It
  cannot be an `organization token`_.

**WORKSPACE_DEPENDENCIES_TABLE** (Required)
  The AWS DynamoDB table to store the workspace dependencies in.

**NOTIFICATION_TOKEN** (Optional, Required if set in TFE)
  The token set on the TFE notification setup. TFE recommends that you use
  tokens on notification in order to allow for HMAC validation of those
  notifications.

Known Limitations
-----------------
- If a run fails to create, there is no retry. Currently we only warn in the logs.
- Recursive remote state dependencies will cause endless runs if the apply is automatic. You should probably never do either of these things...

License: `APL2`_
