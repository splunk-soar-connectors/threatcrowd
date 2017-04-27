# --
# File: threatcrowd_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2016
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
# --

# Phantom Imports below
import phantom.app as phantom
from phantom.app import BaseConnector
from phantom.app import ActionResult

# THIS Connector imports
from threatcrowd_consts import *

# Regular imports below
import requests
import simplejson as json


class ThreatCrowdConnector(BaseConnector):

    # Supported actions
    ACTION_ID_LOOKUP_EMAIL = "lookup_email"
    ACTION_ID_LOOKUP_DOMAIN = "lookup_domain"
    ACTION_ID_LOOKUP_IP = "lookup_ip"
    ACTION_ID_FILE_REPUTATION = "file_reputation"

    def __init__(self):

        super(ThreatCrowdConnector, self).__init__()

    def initialize(self):
        ''' Called once for every action.  All member initializations occur here'''

        # Get the base URL from the consts file
        self._base_url = THREATCROWD_BASE_URL

        # Initialize the headers here for use elsewhere
        self._headers = {'Accept': 'application/json'}

        # The URI is initialized and is used in every rest endpoint call
        self._api_uri = THREATCROWD_API_URI

        return phantom.APP_SUCCESS

    def _make_rest_call(self, endpoint, action_result, params):

        # Build the URL
        call_url = self._base_url + self._api_uri + endpoint

        resp_json = {}

        # Make the rest call
        try:
            r = requests.get(call_url, params=params)
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, THREATCROWD_ERR_SERVER_CONNECTION, e), resp_json)

        # Try to parse the rest call's response
        try:
            resp_json = r.json()
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, THREATCROWD_ERR_JSON_PARSE, e), resp_json)

        # Check the status code if anything useful was returned
        if (200 <= r.status_code <= 399) and resp_json["response_code"] == "1":

            return (phantom.APP_SUCCESS, resp_json)

        elif resp_json["response_code"] == "0":

            return (phantom.APP_ERROR, resp_json)

        else:
            return (action_result.set_status(phantom.APP_ERROR, THREATCROWD_ERR_SERVER_CONNECTION, resp_json))

    def _lookup_domain(self, param):

        # Create an action result to add data to

        action_result = self.add_action_result(ActionResult(param))

        params = {}

        params['domain'] = param[THREATCROWD_JSON_DOMAIN]

        endpoint = THREATCROWD_DOMAIN_URI

        ret_val, response = self._make_rest_call(endpoint, action_result, params)

        if (phantom.is_fail(ret_val)):
            if response["response_code"] == "0":
                action_result.set_summary({'Error': 'Did not receive any information.'})
                return action_result.set_status(phantom.APP_SUCCESS)
            action_result.set_status(phantom.APP_ERROR, "Failure during rest call.", response)
            return phantom.APP_ERROR

        limit = param.get(param[THREATCROWD_JSON_LIMIT], THREATCROWD_DEFAULT_LIMIT)

        keys_to_limit = ["hashes", "subdomains", "resolutions"]
        total_res = len(response["resolutions"])
        if (0 < limit < total_res):
            for resp, val in response.iteritems():
                if resp in keys_to_limit:
                    temp_list = []
                    for x in range(0, limit):
                        if len(response[resp]) > 0:
                            temp_list.append(response[resp][x])
                    response[resp].update(temp_list)

        action_result.add_data(response)
        action_result.update_summary({"total_objects": limit if limit < total_res else total_res})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_email(self, param):

        # Create an action result to add data to

        action_result = self.add_action_result(ActionResult(param))

        params = {}

        params['email'] = param[THREATCROWD_JSON_EMAIL]

        endpoint = THREATCROWD_EMAIL_URI

        ret_val, response = self._make_rest_call(endpoint, action_result, params)

        if (phantom.is_fail(ret_val)):
            if response["response_code"] == "0":
                action_result.set_summary({'Error': 'Did not receive any information.'})
                return action_result.set_status(phantom.APP_SUCCESS)
            action_result.set_status(phantom.APP_ERROR, "Failure during rest call.", response)
            return

        action_result.add_data(response)

        action_result.update_summary({"total_objects": len(response["domains"])})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_ip(self, param):

        # Create an action result to add data to

        action_result = self.add_action_result(ActionResult(param))

        params = {}

        params['ip'] = param[THREATCROWD_JSON_IP]

        endpoint = THREATCROWD_IP_URI

        ret_val, response = self._make_rest_call(endpoint, action_result, params)

        if (phantom.is_fail(ret_val)):
            if response["response_code"] == "0":
                action_result.set_summary({'Error': 'Did not receive any information.'})
                return action_result.set_status(phantom.APP_SUCCESS)
            action_result.set_status(phantom.APP_ERROR, "Failure during rest call.", response)
            return phantom.APP_ERROR

        action_result.add_data(response)

        action_result.update_summary({"total_objects": len(response["resolutions"])})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _file_reputation(self, param):

        # Create an action result
        action_result = self.add_action_result(ActionResult(param))

        # Make an empty params dict in order to pass to the rest call
        params = {}

        # Populate the params
        params['resource'] = param[THREATCROWD_JSON_FILE]

        endpoint = THREATCROWD_FILE_URI

        ret_val, response = self._make_rest_call(endpoint, action_result, params)

        if (phantom.is_fail(ret_val)):
            if response["response_code"] == "0":
                action_result.set_summary({'Error': 'Did not receive any information.'})
                return action_result.set_status(phantom.APP_SUCCESS)
            action_result.set_status(phantom.APP_ERROR, "Failure during rest call.", response)
            return phantom.APP_ERROR

        # Sometimes the scans result will have an empty entry.  This gets rid of it
        count = 0
        for resp in response["scans"]:
            if len(resp) != 0:
                count += 1

        action_result.add_data(response)

        action_result.update_summary({"total_objects": count})

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ''' This is the function that handles all of the actions'''

        # Gets the action that we are supposed to carry out, and set it in the connection result object
        action = self.get_action_identifier()

        # Initialize it to success by default
        ret_val = phantom.APP_SUCCESS

        # Find the right action
        if action == self.ACTION_ID_LOOKUP_DOMAIN:
            ret_val = self._lookup_domain(param)
        elif action == self.ACTION_ID_LOOKUP_EMAIL:
            ret_val = self._lookup_email(param)
        elif action == self.ACTION_ID_LOOKUP_IP:
            ret_val = self._lookup_ip(param)
        elif action == self.ACTION_ID_FILE_REPUTATION:
            ret_val = self._file_reputation(param)

        return ret_val

if __name__ == '__main__':
    """ This section is executed when run in standalone debug mode """

    import sys
    import pudb

    pudb.set_trace()

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=' ' * 4))

        connector = ThreatCrowdConnector()

        connector.print_progress_message = True

        ret_val = connector._handle_action(json.dumps(in_json), None)

        print ret_val

    exit(0)
