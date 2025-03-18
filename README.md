# Cyber Triage for SOAR

Publisher: Basis Technology \
Connector Version: 1.0.5 \
Product Vendor: Basis Technology \
Product Name: Cyber Triage \
Minimum Product Version: 5.2.0

Initiates a remote endpoint collection to support an investigation using Cyber Triage

### Configuration variables

This table lists the configuration variables required to operate Cyber Triage for SOAR. These variables are specified when configuring a Cyber Triage asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**server** | required | string | IP or hostname of a Cyber Triage server |
**api_key** | required | password | API key from a Cyber Triage server |
**username** | required | string | Domain\\Username of an administrative Windows account |
**password** | required | password | Account password |
**verify_server_cert** | required | boolean | Verify the Cyber Triage server certificate |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration \
[scan endpoint](#action-scan-endpoint) - Initiates a Cyber Triage collection on a remote endpoint

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'scan endpoint'

Initiates a Cyber Triage collection on a remote endpoint

Type: **investigate** \
Read only: **True**

This action schedules a collection for a remote endpoint via a Cyber Triage server. The successful run of this action indicates that a collection was scheduled on the Cyber Triage server and does not indicate that a collection was completed. On success the action returns a cyber triage session id which can be used by other actions to query information regarding that session.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** | required | IP or hostname of the Windows endpoint to collect | string | `ip` `host name` |
**malware_scan** | required | Send MD5 hashes to external malware analysis service | boolean | |
**file_upload** | required | Send unknown files to external malware analysis service. Malware scan must be enabled for file upload to occur | boolean | |
**full_scan** | required | Scan entire file system for suspicious files | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip_hostname | string | `ip` `host name` | computer1-vm |
action_result.parameter.malware_scan | string | | True False |
action_result.parameter.file_upload | string | | True False |
action_result.parameter.full_scan | string | | True False |
action_result.status | string | | success failed |
action_result.message | string | | Sessionid: computer1-vm|1509568164801 Error from Cyber Triage server. Status Code: 401 Data from server: Unauthorized. Error from Cyber Triage server. Status Code: 404 Data from server: The network path was not found. |
action_result.data.\*.SessionId | string | `cyber triage session id` | computer1-vm|1509568164801 |
action_result.summary.sessionID | string | | computer1-vm|1509568164801 |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
