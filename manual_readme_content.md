
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
