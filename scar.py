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

from botocore.exceptions import ClientError
import json
import logging
from multiprocessing.pool import ThreadPool
import os
from tabulate import tabulate

from Scar.aws_client import AWSClient
from Scar.aws_lambda import AWSLambda, OutputType
import Scar.command_parser as command_parser
import Scar.scar_utils as scar_utils

logging.basicConfig(filename='scar.log', filemode='w', level=logging.INFO)  
aws_client = AWSClient()
aws_lambda = AWSLambda(aws_client)

MAX_CONCURRENT_INVOCATIONS = 1000


def delete_function_code():
    # Remove the zip created in the operation
    os.remove(aws_lambda.zip_file_path)        


def parse_lambda_function_creation_response(lambda_response):
    if aws_lambda.output == OutputType.VERBOSE:
        logging.info('LambdaOutput', lambda_response)
    elif aws_lambda.output == OutputType.JSON:
        logging.info('LambdaOutput', {'AccessKey' : aws_client.get_access_key(),
                                               'FunctionArn' : lambda_response['FunctionArn'],
                                               'Timeout' : lambda_response['Timeout'],
                                               'MemorySize' : lambda_response['MemorySize'],
                                               'FunctionName' : lambda_response['FunctionName']})
    else:
        print("Function '%s' successfully created." % aws_lambda.name)
        logging.info("Function '%s' successfully created." % aws_lambda.name)


def parse_log_group_creation_response(cw_response):
    if aws_lambda.output == OutputType.VERBOSE:
        logging.info('CloudWatchOuput', cw_response)
    if aws_lambda.output == OutputType.JSON:
        logging.info('CloudWatchOutput', {'RequestId' : cw_response['ResponseMetadata']['RequestId'],
                                                            'HTTPStatusCode' : cw_response['ResponseMetadata']['HTTPStatusCode']})
    else:
        print("Log group '%s' successfully created." % aws_lambda.log_group_name)
        logging.info("Log group '%s' successfully created." % aws_lambda.log_group_name)


def create_function():
    # lambda_validator.validate_function_creation_values(aws_lambda)
    try:
        lambda_response = aws_client.create_function(aws_lambda)
        parse_lambda_function_creation_response(lambda_response)
    except ClientError as ce:
        logging.error("Error initializing lambda function: %s" % ce)
        scar_utils.finish_failed_execution()
    finally:
        delete_function_code()


def create_log_group():
    # lambda_validator.validate_log_creation_values(aws_lambda)
    cw_response = aws_client.create_log_group(aws_lambda)
    parse_log_group_creation_response(cw_response)
    # Set retention policy into the log group
    aws_client.set_log_retention_policy(aws_lambda)

    
def add_event_source():
    bucket_name = aws_lambda.event_source
    try:
        aws_client.check_and_create_s3_bucket(bucket_name)
        aws_client.add_lambda_permissions(aws_lambda.name, bucket_name)
        aws_client.create_trigger_from_bucket(bucket_name, aws_lambda.function_arn)
        if aws_lambda.recursive:
            aws_client.add_s3_bucket_folder(bucket_name, "recursive/")
            aws_client.create_recursive_trigger_from_bucket(bucket_name, aws_lambda.function_arn)
    except ClientError as ce:
        print ("Error creating the event source: %s" % ce)        


def parse_aws_logs(logs, request_id):
    if (logs is None) or (request_id is None):
        return None
    full_msg = ""
    logging = False
    lines = logs.split('\n')
    for line in lines:
        if line.startswith('REPORT') and request_id in line:
            full_msg += line + '\n'
            return full_msg
        if logging:
            full_msg += line + '\n'
        if line.startswith('START') and request_id in line:
            full_msg += line + '\n'
            logging = True


def preheat_function():
    response = aws_client.preheat_function(aws_lambda)
    parse_invocation_response(response)


def launch_lambda_instance():
    response = aws_client.invoke_lambda_function(aws_lambda)
    parse_invocation_response(response)


def parse_invocation_response(response):
    # Decode and parse the payload
    response = scar_utils.parse_payload(response)
    if "FunctionError" in response:
        if "Task timed out" in response['Payload']:
            # Find the timeout time
            message = scar_utils.find_expression('(Task timed out .* seconds)', str(response['Payload']))
            # Modify the error message
            message = message.replace("Task", "Function '%s'" % aws_lambda.name)
            if (aws_lambda.output == OutputType.VERBOSE) or (aws_lambda.output == OutputType.JSON):
                logging.error({"Error" : json.dumps(message)})
            else:
                logging.error("Error: %s" % message)
        else:
            print("Error in function response")
            logging.error("Error in function response: %s" % response['Payload'])
        scar_utils.finish_failed_execution()

    if aws_lambda.is_asynchronous():
        if (aws_lambda.output == OutputType.VERBOSE):
            logging.info('LambdaOutput', response)
        elif (aws_lambda.output == OutputType.JSON):
            logging.info('LambdaOutput', {'StatusCode' : response['StatusCode'],
                                         'RequestId' : response['ResponseMetadata']['RequestId']})
        else:
            logging.info("Function '%s' launched correctly" % aws_lambda.name)
            print("Function '%s' launched correctly" % aws_lambda.name)
    else:
        # Transform the base64 encoded results to something legible
        response = scar_utils.parse_base64_response_values(response)
        # Extract log_group_name and log_stream_name from the payload
        response = scar_utils.parse_log_ids(response)
        if (aws_lambda.output == OutputType.VERBOSE):
            logging.info('LambdaOutput', response)
        elif (aws_lambda.output == OutputType.JSON):
            logging.info('LambdaOutput', {'StatusCode' : response['StatusCode'],
                                         'Payload' : response['Payload'],
                                         'LogGroupName' : response['LogGroupName'],
                                         'LogStreamName' : response['LogStreamName'],
                                         'RequestId' : response['ResponseMetadata']['RequestId']})
        else:
            logging.info('SCAR: Request Id: %s' % response['ResponseMetadata']['RequestId'])
            logging.info(response['Payload'])
            print('Request Id: %s' % response['ResponseMetadata']['RequestId'])
            print(response['Payload'])
        
def process_event_source_calls():
    s3_file_list = aws_client.get_s3_file_list(aws_lambda.event_source)
    logging.info("Files found: '%s'" % s3_file_list)
    # First do a request response invocation to prepare the lambda environment
    if s3_file_list:
        s3_file = s3_file_list.pop(0)
        response = aws_client.launch_request_response_event(aws_lambda, s3_file)
        parse_invocation_response(response)
    # If the list has more elements, invoke functions asynchronously    
    if s3_file_list:
        process_asynchronous_lambda_invocations(s3_file_list)      

 
def process_asynchronous_lambda_invocations(s3_file_list):
    size = len(s3_file_list)
    if size > MAX_CONCURRENT_INVOCATIONS:
        s3_file_chunk_list = scar_utils.divide_list_in_chunks(s3_file_list, MAX_CONCURRENT_INVOCATIONS)
        for s3_file_chunk in s3_file_chunk_list:
            launch_concurrent_lambda_invocations(s3_file_chunk)
    else:
        launch_concurrent_lambda_invocations(s3_file_list)


def launch_concurrent_lambda_invocations(s3_file_list):
    pool = ThreadPool(processes=len(s3_file_list))
    pool.map(
        lambda s3_file: parse_invocation_response(aws_client.launch_async_event(s3_file, aws_lambda)),
        s3_file_list
    )
    pool.close()    


def parse_lambda_info_json_result(function_info):
    name = function_info['Configuration'].get('FunctionName', "-")
    memory = function_info['Configuration'].get('MemorySize', "-")
    timeout = function_info['Configuration'].get('Timeout', "-")
    image_id = function_info['Configuration']['Environment']['Variables'].get('IMAGE_ID', "-")
    return {'Name' : name,
            'Memory' : memory,
            'Timeout' : timeout,
            'Image_id': image_id}


def get_table(functions_info):
    headers = ['NAME', 'MEMORY', 'TIME', 'IMAGE_ID']
    table = []
    for function in functions_info:
        table.append([function['Name'],
                      function['Memory'],
                      function['Timeout'],
                      function['Image_id']])
    return tabulate(table, headers)


def parse_ls_response(lambda_function_info_list):
    # Create the data structure
    if aws_lambda.output == OutputType.VERBOSE:
        functions_full_info = []
        [functions_full_info.append(function_info) for function_info in lambda_function_info_list]
        print('LambdaOutput', functions_full_info)
    else:
        functions_parsed_info = []
        for function_info in lambda_function_info_list:
            lambda_info_parsed = parse_lambda_info_json_result(function_info)
            functions_parsed_info.append(lambda_info_parsed)
        if aws_lambda.output == OutputType.JSON:
            print('Functions', functions_parsed_info)
        else:
            print(get_table(functions_parsed_info))


def init():
    # Call the AWS services
    create_function()
    create_log_group()
    if aws_lambda.event_source:
        add_event_source()
    # If preheat is activated, the function is launched at the init step
    if aws_lambda.preheat:    
        preheat_function()


def run():
    if aws_lambda.has_event_source():
        process_event_source_calls()               
    else:
        launch_lambda_instance()
        

def ls():
    # Get the filtered resources from AWS
    lambda_function_info_list = aws_client.get_all_functions()
    parse_ls_response(lambda_function_info_list)


def rm():
    if aws_lambda.delete_all:
        aws_client.delete_all_resources(aws_lambda)
    else:
        aws_client.delete_resources(aws_lambda.name, aws_lambda.output)


def log():
    try:
        full_msg = ""
        if aws_lambda.log_stream_name:
            response = aws_client.get_log_events_by_group_name_and_stream_name(
                aws_lambda.log_group_name,
                aws_lambda.log_stream_name )
            for event in response['events']:
                full_msg += event['message']
        else:
            response = aws_client.get_log_events_by_group_name(aws_lambda.log_group_name)
            data = []

            for event in response['events']:
                data.append((event['message'], event['timestamp']))

            while(('nextToken' in response) and response['nextToken']):
                response = aws_client.get_log_events_by_group_name(aws_lambda.log_group_name, response['nextToken'])
                for event in response['events']:
                    data.append((event['message'], event['timestamp']))

            sorted_data = sorted(data, key=lambda time: time[1])
            for sdata in sorted_data:
                full_msg += sdata[0]

        response['completeMessage'] = full_msg
        if aws_lambda.request_id:
            print (parse_aws_logs(full_msg, aws_lambda.request_id))
        else:
            print (full_msg)

    except ClientError as ce:
        print(ce)

def create_argparser(parser):
    subparsers = parser.add_subparsers(title='Commands')    
    command_parser.create_init_parser(subparsers, init)
    command_parser.create_run_parser(subparsers, run)
    command_parser.create_rm_parser(subparsers, rm)
    command_parser.create_ls_parser(subparsers, ls)
    command_parser.create_log_parser(subparsers, log)
    return parser 
                      
if __name__ == "__main__":
    logging.info('----------------------------------------------------')
    logging.info('SCAR execution started')    
    aws_lambda.check_config_file()
    parser = command_parser.get_argparser()
    create_argparser(parser)
    args = command_parser.parse_arguments(parser)
    aws_lambda.set_attributes(args)
    args.func()
    logging.info('SCAR execution finished')
    logging.info('----------------------------------------------------')   
