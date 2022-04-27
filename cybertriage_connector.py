#
# Cyber Triage Phantom App
#
# Apache 2.0
# Contact: support <at> cybertriage <dot> com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import json

# Phantom App imports
import phantom.app as phantom
# Usage of the consts file is recommended
from cybertriage_consts import *
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


# Phantom calls the following methods from CyberTriageConnector whenever
# a Cyber Triage action is used: initialize(), handle_action(), and finalize()
class CyberTriageConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(CyberTriageConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        self._base_url = None

    # Processs an empty response. Only return APP_SUCCESS if the http status code is 200
    # otherwise return APP_ERROR with an error message.
    #
    # Args:
    #  r:             (response)      is a requests response object
    #  action_result: (action_result) is an action_result object
    #
    # Returns: A RetVal tuple containing (APP_ERROR,None) or (APP_SUCCESS,{})
    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    # Processs an html response. Assumes that rest calls always return json and any html response is an error.
    #
    # Args:
    #  r:             (response)      is a requests response object
    #  action_result: (action_result) is an action_result object
    #
    # Returns: A RetVal tuple containing (APP_ERROR,None)
    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    # Processs a json response. Used to validate/extract the json response from a response object. if the http status code is between 200 and 399
    # then APP_SUCCESS otherwise json response contains an error message and APP_ERROR is returned.
    #
    # Args:
    #  r:             (response)      is a requests response object
    #  action_result: (action_result) is an action_result object
    #
    # Returns: A RetVal tuple containing (APP_ERROR,None) or (APP_SUCCESS,json response)
    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # Format error message based on error response in json
        json_err_msg = 'No Error Message'
        if 'Error' in resp_json:
            json_err_msg = resp_json['Error']

        elif 'message' in resp_json:
            json_err_msg = resp_json['message']

        message = "Error from Cyber Triage server. Status Code: {0} Data from server: {1}".format(
                r.status_code, json_err_msg)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    # Used to determine how to process an http response. 1 of 3 methods will be called depending on
    # if the response is json, html or empty. All other scenarios will retuls in an APP_ERROR.
    #
    # Args:
    #  r:             (response)      is a requests response object
    #  action_result: (action_result) is a action_result object
    #
    # Returns: A RetVal tuple which contains the status of the app (APP_ERROR or APP_SUCCESS) and a json response if APP_SUCCESS
    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    # Phantom wrapper around the Requests module to make creating http requests and handling errors easier.
    #
    # Args:
    #  endpoint:      (str)           a rest endpoint - not including the base url.
    #                                 ex "/livesessions" is passed in instead of https://server:9443/api/livesessions
    #  action_result: (action_result) an action result object
    #  headers:       (dict)          a dictionary of http headers
    #  params:        (dict)          a dictionary of params that are converted into a query string in the url
    #  data:          (dict)          a dictonary when using POST method
    #  method:        (str)           a valid http method (get, post, delete, put, etc...)
    #
    # Returns: A RetVal tuple containing APP_ERROR/APP_SUCCESS and a  request response object
    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                            url,
                            json=data,
                            headers=headers,
                            verify=self.verify_server_cert,
                            params=params)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR,
                "Error Connecting to Cyber Triage server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    # Implements the test_connectivity action which veifies if a Cyber Triage server can be reached
    # given the parameters provided via the Cyber Triage correlation/checkcredentials API
    #
    # Args:
    #  param (dict): A dictionary of parameters from the test_connectivity action defined in cybertriage.json
    #
    # Returns: APP_ERROR or APP_SUCCESS
    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")

        # make rest call
        ret_val, response = self._make_rest_call('/correlation/checkcredentials', action_result, params=None, headers=self.api_headers)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            self.save_progress("Test Connectivity Failed.")
            self.save_progress("{0}".format(action_result.get_message()))
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    # Implements the scan_endpoint action which initiates a remote collection on an endpoing via
    # the Cyber Triage /livesessions API.
    #
    # Args:
    #  param (dict): A dictionary of parameters from the scan_endpoint action defined in cybertriage.json
    #
    # Returns: APP_ERROR or APP_SUCCESS
    def _handle_scan_endpoint(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        endpoint = param['ip_hostname']
        is_mal_scan_on = param['malware_scan']
        is_file_upload_on = param['file_upload']
        is_fast_scan_on = not(param['full_scan'])

        # Make data dict for rest call
        api_data = {'hostName': endpoint}
        api_data.update({'userId': self.win_user})
        api_data.update({'password': self.win_pass})
        api_data.update({'malwareScanRequested': is_mal_scan_on})
        api_data.update({'sendContent': is_file_upload_on})
        api_data.update({'fastScan': is_fast_scan_on})
        api_data.update({'sendIpAddress': False})

        # make rest call
        ret_val, response = self._make_rest_call('/livesessions',
            action_result, params=None, headers=self.api_headers, data=api_data, method="post")

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        if "SessionId" in response:
            summary['sessionID'] = response['SessionId']

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    # This is where action handling begins. handle_action is called for all actions and is responsible for
    # calling the correct action handler based on the action id.
    #
    # Args:
    #  param: (dict) A dictionary of action parameters
    #
    # Returns: APP_ERROR or APP_SUCCESS
    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'scan_endpoint':
            ret_val = self._handle_scan_endpoint(param)

        return ret_val

    # This is the first method called whenever one of our apps actions are used within phantom.
    # It is used to setup and initialize anything that our app needs.
    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        # Required values can be accessed directly
        self.server = config['server']
        self.api_key = config['api_key']
        self.win_user = config['username']
        self.win_pass = config['password']
        self.verify_server_cert = config['verify_server_cert']
        self._base_url = "https://" + self.server + ":9443/api"
        self.api_headers = {'restApiKey': self.api_key}

        return phantom.APP_SUCCESS

    # This is the last method called whenever one of our apps actions are used within phantom.
    # It is used to cleanup/free resources.
    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


# This is only used for testing/debugging purposes when calling the file as a script.
# It is not used within the Phantom UI
if __name__ == '__main__':

    import argparse
    import sys

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if (len(sys.argv) < 2):
        print("No test json specified as input")
        exit(0)

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=verify, timeout=CYBERTRIAGE_DEFAULT_REQUEST_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=verify, data=data, headers=headers,
                               timeout=CYBERTRIAGE_DEFAULT_REQUEST_TIMEOUT)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CyberTriageConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
