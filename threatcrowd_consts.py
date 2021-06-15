# File: threatcrowd_consts.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

THREATCROWD_JSON_DOMAIN = "domain"
THREATCROWD_JSON_EMAIL = "email"
THREATCROWD_JSON_IP = "ip"
THREATCROWD_JSON_FILE = "hash"
THREATCROWD_JSON_LIMIT = "response_limit"
THREATCROWD_BASE_URL = "https://www.threatcrowd.org/"
THREATCROWD_API_URI = "searchApi/v2/"
THREATCROWD_ERR_SERVER_CONNECTION = "Could not successfully connect to the Threatcrowd API"
THREATCROWD_DOMAIN_URI = "domain/report/"
THREATCROWD_EMAIL_URI = "email/report/"
THREATCROWD_IP_URI = "ip/report/"
THREATCROWD_FILE_URI = "file/report/"
THREATCROWD_DEFAULT_LIMIT = 10

# This value is set by trial and error by quering ThreatCrowd
THREATCROWD_ERR_CODE_UNAVAILABLE = "Error code unavailable"
THREATCROWD_ERR_MESSAGE_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
THREATCROWD_UNICODE_DAMMIT_TYPE_ERROR_MESSAGE = "Error occurred while connecting to the ThreatCrowd server. Please check the asset configuration and|or the action parameters"

# Integer Validation Keys
THREATCROWD_VALIDATE_INTEGER = "Please provide a valid integer value in the '{param}' parameter"
THREATCROWD_NON_ZERO_NON_NEG_INVALID_PARAM = "Please provide a non-zero positive integer value in the '{param}' parameter"
THREATCROWD_NON_NEG_PARAM = "Please provide a valid non-negative integer value in the '{param}' parameter"
