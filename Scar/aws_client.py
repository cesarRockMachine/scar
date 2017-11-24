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

import boto3
import botocore
from botocore.exceptions import ClientError
from botocore.vendored.requests.exceptions import ReadTimeout
import json
import uuid

from Scar.result import Result
import Scar.scar_utils as scar_utils

# Default values
botocore_client_read_timeout = 360
default_aws_region = "us-east-1"

def create_function_name(image_id_or_path):
    parsed_id_or_path = image_id_or_path.replace('/', ',,,').replace(':', ',,,').replace('.', ',,,').split(',,,')
    name = 'scar-%s' % '-'.join(parsed_id_or_path)
    i = 1
    while find_function_name(name):
        name = 'scar-%s-%s' % ('-'.join(parsed_id_or_path), str(i))
        i = i + 1
    return name

def check_memory(lambda_memory):
    """ Check if the memory introduced by the user is correct.
    If the memory is not specified in 64mb increments,
    transforms the request to the next available increment."""
    if (lambda_memory < 128) or (lambda_memory > 1536):
        raise Exception('Incorrect memory size specified')
    else:
        res = lambda_memory % 64
        if (res == 0):
            return lambda_memory
        else:
            return lambda_memory - res + 64

def check_time(lambda_time):
    if (lambda_time <= 0) or (lambda_time > 300):
        raise Exception('Incorrect time specified')
    return lambda_time

def get_user_name_or_id():
    try:
        user = get_iam().get_user()['User']
        return user.get('UserName', user['UserId'])
    except ClientError as ce:
        # If the user doesn't have access rights to IAM
        return scar_utils.find_expression('(?<=user\/)(\S+)', str(ce))

def get_access_key():
    session = boto3.Session()
    credentials = session.get_credentials()
    return credentials.access_key

def get_boto3_client(client_name, region=None):
    if region is None:
        region = default_aws_region
    boto_config = botocore.config.Config(read_timeout=botocore_client_read_timeout)            
    return boto3.client(client_name, region_name=region, config=boto_config)

def get_lambda(region=None):
    return get_boto3_client('lambda', region)

def get_log(region=None):
    return get_boto3_client('logs', region)

def get_iam(region=None):
    return get_boto3_client('iam', region)

def get_resource_groups_tagging_api(region=None):
    return get_boto3_client('resourcegroupstaggingapi', region)

def get_s3(region=None):
    return get_boto3_client('s3', region)

def get_s3_file_list(bucket_name):
    file_list = []
    result = get_s3().list_objects_v2(Bucket=bucket_name, Prefix='input/')
    if 'Contents' in result:
        for content in result['Contents']:
            if content['Key'] and content['Key'] != "input/":
                file_list.append(content['Key'])
    return file_list

def find_function_name(function_name):
    try:
        paginator = get_lambda().get_paginator('list_functions')
        for functions in paginator.paginate():
            for lfunction in functions['Functions']:
                if function_name == lfunction['FunctionName']:
                    return True
        return False
    except ClientError as ce:
        print ("Error listing the lambda functions: %s" % ce)
        scar_utils.force_finish_failed_execution()

def check_function_name_not_exists(function_name):
    if not find_function_name(function_name):
        print("Error: Function '%s' doesn't exist." % function_name)
        scar_utils.force_finish_failed_execution()

def check_function_name_exists(function_name):
    if find_function_name(function_name):
        print ("Error: Function '%s' already exists." % function_name)
        scar_utils.force_finish_failed_execution()

def update_function_timeout(function_name, timeout):
    try:
        get_lambda().update_function_configuration(FunctionName=function_name,
                                                               Timeout=check_time(timeout))
    except ClientError as ce:
        print ("Error updating lambda function timeout: %s" % ce)

def update_function_memory(function_name, memory):
    try:
        get_lambda().update_function_configuration(FunctionName=function_name,
                                                               MemorySize=memory)
    except ClientError as ce:
        print ("Error updating lambda function memory: %s" % ce)

def get_function_environment_variables(function_name):
    return get_lambda().get_function(FunctionName=function_name)['Configuration']['Environment']

def parse_environment_variables(lambda_env_variables, env_vars):
    for var in env_vars:
        var_parsed = var.split("=")
        # Add an specific prefix to be able to find the variables defined by the user
        lambda_env_variables['Variables']['CONT_VAR_' + var_parsed[0]] = var_parsed[1] 

def update_function_env_variables(function_name, env_vars):
    try:
        # Retrieve the global variables already defined
        lambda_env_variables = get_function_environment_variables(function_name)
        parse_environment_variables(lambda_env_variables, env_vars)
        get_lambda().update_function_configuration(FunctionName=function_name,
                                                                Environment=lambda_env_variables)
    except ClientError as ce:
        print ("Error updating the environment variables of the lambda function: %s" % ce)

def create_trigger_from_bucket(bucket_name, function_arn):
    notification = { "LambdaFunctionConfigurations": [
                        { "LambdaFunctionArn": function_arn,
                          "Events": [ "s3:ObjectCreated:*" ],
                          "Filter":
                            { "Key":
                                { "FilterRules": [
                                    { "Name": "prefix",
                                      "Value": "input/"
                                    }]
                                }
                            }
                        }]
                    }
    try:
        get_s3().put_bucket_notification_configuration( Bucket=bucket_name,
                                                             NotificationConfiguration=notification )
    except ClientError as ce:
        print ("Error configuring S3 bucket: %s" % ce)
        
def create_recursive_trigger_from_bucket(bucket_name, function_arn):
    notification = { "LambdaFunctionConfigurations": [
                        { "LambdaFunctionArn": function_arn,
                          "Events": [ "s3:ObjectCreated:*" ],
                          "Filter":
                            { "Key":
                                { "FilterRules": [
                                    { "Name": "prefix",
                                      "Value": "input/"
                                    }]
                                }
                            }
                        },
                        { "LambdaFunctionArn": function_arn,
                          "Events": [ "s3:ObjectCreated:*" ],
                          "Filter":
                            { "Key":
                                { "FilterRules": [
                                    { "Name": "prefix",
                                      "Value": "recursive/"
                                    }]
                                }
                            }
                        }]
                    }
    try:
        get_s3().put_bucket_notification_configuration( Bucket=bucket_name,
                                                             NotificationConfiguration=notification )

    except ClientError as ce:
        print ("Error configuring S3 bucket: %s" % ce)            

def add_lambda_permissions(lambda_name, bucket_name):
    try:
        get_lambda().add_permission(FunctionName=lambda_name,
                                         StatementId=str(uuid.uuid4()),
                                         Action="lambda:InvokeFunction",
                                         Principal="s3.amazonaws.com",
                                         SourceArn='arn:aws:s3:::%s' % bucket_name
                                        )
    except ClientError as ce:
        print ("Error setting lambda permissions: %s" % ce)

def check_and_create_s3_bucket(bucket_name):
    try:
        buckets = get_s3().list_buckets()
        # Search for the bucket
        found_bucket = [bucket for bucket in buckets['Buckets'] if bucket['Name'] == bucket_name]
        if not found_bucket:
            # Create the bucket if not found
            create_s3_bucket(bucket_name)
        # Add folder structure
        add_s3_bucket_folder(bucket_name, "input/")
        add_s3_bucket_folder(bucket_name, "output/")
    except ClientError as ce:
        print ("Error getting the S3 buckets list: %s" % ce)

def create_s3_bucket(bucket_name):
    try:
        get_s3().create_bucket(ACL='private', Bucket=bucket_name)
    except ClientError as ce:
        print ("Error creating the S3 bucket '%s': %s" % (bucket_name, ce))

def add_s3_bucket_folder(bucket_name, folder_name):
    try:
        get_s3().put_object(Bucket=bucket_name, Key=folder_name)
    except ClientError as ce:
        print ("Error creating the S3 bucket '%s' folders: %s" % (bucket_name, ce))

def get_functions_arn_list():
    arn_list = []
    try:
        # Creation of a function filter by tags
        client = get_resource_groups_tagging_api()
        tag_filters = [ { 'Key': 'owner', 'Values': [ get_user_name_or_id() ] },
                        { 'Key': 'createdby', 'Values': ['scar'] } ]
        response = client.get_resources(TagFilters=tag_filters,
                                             TagsPerPage=100)

        for function in response['ResourceTagMappingList']:
            arn_list.append(function['ResourceARN'])

        while ('PaginationToken' in response) and (response['PaginationToken']):
            response = client.get_resources(PaginationToken=response['PaginationToken'],
                                            TagFilters=tag_filters,
                                            TagsPerPage=100)
            for function in response['ResourceTagMappingList']:
                arn_list.append(function['ResourceARN'])

    except ClientError as ce:
        print ("Error getting function arn by tag: %s" % ce)

    return arn_list

def get_all_functions():
    function_list = []
    # Get the filtered resources from AWS
    functions_arn = get_functions_arn_list()
    try:
        for function_arn in functions_arn:
            function_list.append(get_lambda().get_function(FunctionName=function_arn))
    except ClientError as ce:
        print ("Error getting function info by arn: %s" % ce)
    return function_list

def delete_lambda_function(function_name, result):
    try:
        # Delete the lambda function
        lambda_response = get_lambda().delete_function(FunctionName=function_name)
        result.append_to_verbose('LambdaOutput', lambda_response)
        result.append_to_json('LambdaOutput', { 'RequestId' : lambda_response['ResponseMetadata']['RequestId'],
                                     'HTTPStatusCode' : lambda_response['ResponseMetadata']['HTTPStatusCode'] })
        result.append_to_plain_text("Function '%s' successfully deleted." % function_name)
    except ClientError as ce:
        print ("Error deleting the lambda function: %s" % ce)

def delete_cloudwatch_group(function_name, result):
    try:
        # Delete the cloudwatch log group
        log_group_name = '/aws/lambda/%s' % function_name
        cw_response = get_log().delete_log_group(logGroupName=log_group_name)
        result.append_to_verbose('CloudWatchOutput', cw_response)
        result.append_to_json('CloudWatchOutput', { 'RequestId' : cw_response['ResponseMetadata']['RequestId'],
                                         'HTTPStatusCode' : cw_response['ResponseMetadata']['HTTPStatusCode'] })
        result.append_to_plain_text("Log group '%s' successfully deleted." % function_name)
    except ClientError as ce:
        if ce.response['Error']['Code'] == 'ResourceNotFoundException':
            result.add_warning_message("Cannot delete log group '%s'. Group not found." % log_group_name)
        else:
            print ("Error deleting the cloudwatch log: %s" % ce)

def delete_resources(function_name, args):
    result = Result(args)
    check_function_name_not_exists(function_name)
    delete_lambda_function(function_name, result)
    delete_cloudwatch_group(function_name, result)
    return result

def invoke_function(function_name, invocation_type, log_type, payload):
    response = {}
    try:
        response = get_lambda().invoke(FunctionName=function_name,
                                            InvocationType=invocation_type,
                                            LogType=log_type,
                                            Payload=payload)
    except ClientError as ce:
        print ("Error invoking lambda function: %s" % ce)
        scar_utils.force_finish_failed_execution()

    except ReadTimeout as rt:
        print ("Timeout reading connection pool: %s" % rt)
        scar_utils.force_finish_failed_execution()
    return response

def preheat_function(aws_client, args):
    args.async = False
    launch_lambda_instance(aws_client, args, 'RequestResponse', 'Tail', "")

def launch_async_event(s3_file, event, aws_client, args):
    args.async = True
    launch_event(s3_file, event, aws_client, args, 'Event', 'None')
    
def launch_request_response_event(s3_file, event, aws_client, args):
    args.async = False
    launch_event(s3_file, event, aws_client, args, 'RequestResponse', 'Tail')        

def launch_event(s3_file, event, aws_client, args, invocation_type, log_type):
    event['Records'][0]['s3']['object']['key'] = s3_file
    payload = json.dumps(event)
    print("Sending event for file '%s'" % s3_file)
    launch_lambda_instance(aws_client, args, invocation_type, log_type, payload)

def launch_lambda_instance(aws_client, args, invocation_type, log_type, payload):
    '''
    aws_client: generic AwsClient
    args: function arguments generated by the CmdParser
    invocation_type: RequestResponse' or 'Event'
    log_type: 'Tail' or 'None', related with the previous parameter
    payload: json formated string (e.g. json.dumps(data))
    '''
    response = aws_client.invoke_function(args.name, invocation_type, log_type, payload)
    parse_response(response, args.name, args.async, args.json, args.verbose)

def parse_response(response, function_name, async, json, verbose):
    # Decode and parse the payload
    response = scar_utils.parse_payload(response)
    if "FunctionError" in response:
        if "Task timed out" in response['Payload']:
            # Find the timeout time
            message = scar_utils.find_expression('(Task timed out .* seconds)', str(response['Payload']))
            # Modify the error message
            message = message.replace("Task", "Function '%s'" % function_name)
            if verbose or json:
                scar_utils.print_json({"Error" : message})
            else:
                print ("Error: %s" % message)
        else:
            print ("Error in function response: %s" % response['Payload'])
        scar_utils.force_finish_failed_execution()


    result = Result()
    if async:
        # Prepare the outputs
        result.append_to_verbose('LambdaOutput', response)
        result.append_to_json('LambdaOutput', {'StatusCode' : response['StatusCode'],
                                                   'RequestId' : response['ResponseMetadata']['RequestId']})
        result.append_to_plain_text("Function '%s' launched correctly" % function_name)

    else:
        # Transform the base64 encoded results to something legible
        response = scar_utils.parse_base64_response_values(response)
        # Extract log_group_name and log_stream_name from the payload
        response = scar_utils.parse_log_ids(response)
        # Prepare the outputs
        result.append_to_verbose('LambdaOutput', response)
        result.append_to_json('LambdaOutput', {'StatusCode' : response['StatusCode'],
                                               'Payload' : response['Payload'],
                                               'LogGroupName' : response['LogGroupName'],
                                               'LogStreamName' : response['LogStreamName'],
                                               'RequestId' : response['ResponseMetadata']['RequestId']})

        result.append_to_plain_text('SCAR: Request Id: %s' % response['ResponseMetadata']['RequestId'])
        result.append_to_plain_text(response['Payload'])

    # Show results
    result.print_results(json=json, verbose=verbose)