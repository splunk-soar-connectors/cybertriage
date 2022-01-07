[comment]: # "Auto-generated SOAR connector documentation"
# Cyber Triage

Publisher: Basis Technology  
Connector Version: 1\.0\.3  
Product Vendor: Basis Technology  
Product Name: Cyber Triage  
Product Version Supported (regex): "2\.1\.8"  
Minimum Product Version: 3\.0\.251  

Initiates a remote endpoint collection to support an investigation using Cyber Triage


[Cyber Triage](https://www.cybertriage.com/?utm_source=Phantom) allows you to perform a
mini-forensic investigation on an endpoint. It pushes a collection tool to the remote endpoint to
collect volatile and file system data and analyzes the data.

This plug-in allows you to perform a collection as part of your playbook. It requires that you have
the Team version of Cyber Triage.

The primary action of this plug-in is **scan endpoint** , which sends the Cyber Triage collection
tool to the specified endpoint. To use this action, you must specify:

-   Target endpoint
-   Username with admin privileges
-   Password of the admin user

To setup the action, you will need to specify the:

-   Hostname of the Cyber Triage server / REST API
-   Server key (that you can get from the Cyber Triage Server options panel)

The **test connectivity** action allows you to test that Phantom can communicate with the Cyber
Triage server.

If you configured Cyber Triage to use your own SSL certificate, then change the
**verify_server_cert** property to true and import your certificate into [Phantom Certificate
Store](https://my.phantom.us/kb/16/) .

If you have any problems, then please email support@cybertriage.com.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Cyber Triage asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**server** |  required  | string | IP or hostname of a Cyber Triage server
**api\_key** |  required  | password | API key from a Cyber Triage server
**username** |  required  | string | Domain\\Username of an administrative Windows account
**password** |  required  | password | Account password
**verify\_server\_cert** |  required  | boolean | Verify the Cyber Triage server certificate

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[scan endpoint](#action-scan-endpoint) - Initiates a Cyber Triage collection on a remote endpoint  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'scan endpoint'
Initiates a Cyber Triage collection on a remote endpoint

Type: **investigate**  
Read only: **True**

This action schedules a collection for a remote endpoint via a Cyber Triage server\. The successful run of this action indicates that a collection was scheduled on the Cyber Triage server and does not indicate that a collection was completed\. On success the action returns a cyber triage session id which can be used by other actions to query information regarding that session\. 

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | IP or hostname of the Windows endpoint to collect | string |  `ip`  `host name` 
**malware\_scan** |  required  | Send MD5 hashes to external malware analysis service | boolean | 
**file\_upload** |  required  | Send unknown files to external malware analysis service\. Malware scan must be enabled for file upload to occur | boolean | 
**full\_scan** |  required  | Scan entire file system for suspicious files | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.malware\_scan | string | 
action\_result\.parameter\.file\_upload | string | 
action\_result\.parameter\.full\_scan | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.data\.\*\.SessionId | string |  `cyber triage session id` 
action\_result\.summary\.sessionID | string | 