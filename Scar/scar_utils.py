#! /usr/bin/python

# SCAR - Serverless Container-aware ARchitectures
# Copyright (C) GRyCAP - I3M - UPV
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import json
import re
import sys

def force_finish_failed_execution():
    sys.exit(1)
    
def force_finish_successful_execution():
    sys.exit(0)

def validate_function_name(name):
    aws_name_regex = "((arn:(aws|aws-us-gov):lambda:)?([a-z]{2}(-gov)?-[a-z]+-\d{1}:)?(\d{12}:)?(function:)?([a-zA-Z0-9-]+)(:($LATEST|[a-zA-Z0-9-]+))?)"
    pattern = re.compile(aws_name_regex)
    func_name = pattern.match(name)
    return func_name and (func_name.group() == name)

def find_expression(rgx_pattern, string_to_search):
    '''Returns the first group that matches the rgx_pattern in the string_to_search'''
    pattern = re.compile(rgx_pattern)
    match = pattern.search(string_to_search)
    if match :
        return match.group()

def base64_to_utf8(value):
    return base64.b64decode(value).decode('utf8')

def escape_list(values):
    result = []
    for value in values:
        result.append(escape_string(value))
    return str(result).replace("'", "\"")

def escape_string(value):
    value = value.replace("\\", "\\/").replace('\n', '\\n')
    value = value.replace('"', '\\"').replace("\/", "\\/")
    value = value.replace("\b", "\\b").replace("\f", "\\f")
    return value.replace("\r", "\\r").replace("\t", "\\t")

def parse_payload(value):
    value['Payload'] = value['Payload'].read().decode("utf-8")[1:-1].replace('\\n', '\n')
    return value

def parse_base64_response_values(value):
    value['LogResult'] = base64_to_utf8(value['LogResult'])
    value['ResponseMetadata']['HTTPHeaders']['x-amz-log-result'] = base64_to_utf8(value['ResponseMetadata']['HTTPHeaders']['x-amz-log-result'])
    return value

def parse_log_ids(value):
    parsed_output = value['Payload'].split('\n')
    value['LogGroupName'] = parsed_output[1][22:]
    value['LogStreamName'] = parsed_output[2][23:]
    return value

def print_json(value):
    print(json.dumps(value))
