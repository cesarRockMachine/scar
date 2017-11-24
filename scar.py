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

import json
import os
import shutil
import zipfile
import pprint
from botocore.exceptions import ClientError
from multiprocessing.pool import ThreadPool
import Scar.command_parser as command_parser
import Scar.scar_utils as scar_utils
import Scar.config as config
from Scar.result import Result
import Scar.aws_client as aws_client

def set_binary_or_container(args):
    if os.path.isdir(args.image_id_or_path):
        config.Lambda.is_binary = True
    else:
        config.Lambda.is_container = True
        config.Lambda.lambda_env_variables['Variables']['IMAGE_ID'] = args.image_id_or_path
    
def set_function_name(args):
    if not args.name:
        config.Lambda.lambda_name = aws_client.create_function_name(args.image_id_or_path)
    else:
        config.Lambda.lambda_name = args.name
        
def set_function_handler_name():
    config.Lambda.lambda_handler = config.Lambda.lambda_name + ".lambda_handler"
            
def validate_function_name():
    if not scar_utils.validate_function_name(config.Lambda.lambda_name):
        print ("Error: Function name '%s' is not valid." % config.Lambda.lambda_name)
        scar_utils.force_finish_failed_execution()
    
def check_function_existence():
    aws_client.check_function_name_exists(config.Lambda.lambda_name)         

def create_code_package(args):
    config.Lambda.lambda_code = {"ZipFile": create_zip_file(config.Lambda.lambda_name, args)}

def set_function_memory(args):
    if hasattr(args, 'memory') and args.memory:
        config.Lambda.lambda_memory = aws_client.check_memory(args.memory)        

def set_function_running_time(args):
    if hasattr(args, 'time') and args.time:
        config.Lambda.lambda_time = aws_client.check_time(args.time)

def set_function_description(args):            
    if hasattr(args, 'description') and args.description:
        config.Lambda.lambda_description = args.description       

def set_lambda_function_role(args):
    if hasattr(args, 'lambda_role') and args.lambda_role:
        config.Lambda.lambda_role = args.lambda_role
            
def set_function_threshold(args):
    if hasattr(args, 'time_threshold') and args.time_threshold:
        config.Lambda.lambda_env_variables['Variables']['TIME_THRESHOLD'] = str(args.time_threshold)
    else:
        config.Lambda.lambda_env_variables['Variables']['TIME_THRESHOLD'] = str(config.Lambda.lambda_timeout_threshold)

def set_recursive_property(args):
    if hasattr(args, 'recursive') and args.recursive:
        config.Lambda.lambda_env_variables['Variables']['RECURSIVE'] = str(True)
            
def set_environment_variables(args):
    if hasattr(args, 'env') and args.env:
        aws_client.parse_environment_variables(args.env)        
            
def set_function_owner():
    config.Lambda.lambda_tags['owner'] = aws_client.get_user_name_or_id()               

def delete_function_code():
    # Remove the zip created in the operation
    os.remove(config.Lambda.zip_file_path)        

def parse_function_results(result, lambda_response):
    result.append_to_verbose('LambdaOutput', lambda_response)
    result.append_to_json('LambdaOutput', {'AccessKey' : aws_client.get_access_key(),
                                           'FunctionArn' : lambda_response['FunctionArn'],
                                           'Timeout' : lambda_response['Timeout'],
                                           'MemorySize' : lambda_response['MemorySize'],
                                           'FunctionName' : lambda_response['FunctionName']})
    result.append_to_plain_text("Function '%s' successfully created." % config.Lambda.lambda_name)        

def create_function(result):
    """Creates the lambda function.
    Returns the function arn.
    """        
    try:
        lambda_response = aws_client.get_lambda().create_function(FunctionName=config.Lambda.lambda_name,
                                                     Runtime=config.Lambda.lambda_runtime,
                                                     Role=config.Lambda.lambda_role,
                                                     Handler=config.Lambda.lambda_handler,
                                                     Code=config.Lambda.lambda_code,
                                                     Environment=config.Lambda.lambda_env_variables,
                                                     Description=config.Lambda.lambda_description,
                                                     Timeout=config.Lambda.lambda_time,
                                                     MemorySize=config.Lambda.lambda_memory,
                                                     Tags=config.Lambda.lambda_tags)
        parse_function_results(result,  lambda_response)
    except ClientError as ce:
        print ("Error initializing lambda function: %s" % ce)
        scar_utils.force_finish_failed_execution()
    finally:
        delete_function_code()
    return lambda_response['FunctionArn']      

def create_log_group(result):
    log_group_name = '/aws/lambda/' + config.Lambda.lambda_name
    try:
        cw_response = aws_client.get_log().create_log_group(
            logGroupName=log_group_name,
            tags={ 'owner' : aws_client.get_user_name_or_id(),
                   'createdby' : 'scar' }
        )
        # Parse results
        result.append_to_verbose('CloudWatchOuput', cw_response)
        result.append_to_json('CloudWatchOutput', {'RequestId' : cw_response['ResponseMetadata']['RequestId'],
                                                   'HTTPStatusCode' : cw_response['ResponseMetadata']['HTTPStatusCode']})
        result.append_to_plain_text("Log group '/aws/lambda/%s' successfully created." % config.Lambda.lambda_name)

    except ClientError as ce:
        if ce.response['Error']['Code'] == 'ResourceAlreadyExistsException':
            result.add_warning_message("Using existent log group '%s'" % log_group_name)
        else:
            print ("Error creating log groups: %s" % ce)
    # Set retention policy into the log group
    try:
        aws_client.get_log().put_retention_policy(logGroupName=log_group_name,
                                                    retentionInDays=30)
    except ClientError as ce:
        print ("Error setting log retention policy: %s" % ce)
    
def add_event_source(args, function_arn):
    if hasattr(args, 'event_source') and args.event_source:
        bucket_name = args.event_source
        try:
            aws_client.check_and_create_s3_bucket(bucket_name)
            aws_client.add_lambda_permissions(bucket_name)
            aws_client.create_trigger_from_bucket(bucket_name, function_arn)
            if args.recursive:
                aws_client.add_s3_bucket_folder(bucket_name, "recursive/")
                aws_client.create_recursive_trigger_from_bucket(bucket_name, function_arn)
        except ClientError as ce:
            print ("Error creating the event source: %s" % ce)        

def preheat_function(args):
    if hasattr(args, 'preheat') and args.preheat:
        aws_client.preheat_function( args)
    
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

def divide_list_in_chunks(elements, chunk_size):
    """Yield successive n-sized chunks from th elements list."""
    if len(elements) == 0:
        yield []
    for i in range(0, len(elements), chunk_size):
        yield elements[i:i + chunk_size]

def create_zip_file(file_name, args):
    # Set generic lambda function name
    function_name = file_name + '.py'
    # Copy file to avoid messing with the repo files
    # We have to rename because the function name afects the handler name
    shutil.copy(config.Lambda.dir_path + '/lambda/scarsupervisor.py', function_name)
    # Zip the function file
    with zipfile.ZipFile(config.Lambda.zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Lambda function code
        zf.write(function_name)
        # Udocker script code
        zf.write(config.Lambda.dir_path + '/lambda/udocker', 'udocker')
        # Udocker libs
        zf.write(config.Lambda.dir_path + '/lambda/udocker-1.1.0-RC2.tar.gz', 'udocker-1.1.0-RC2.tar.gz')
        os.remove(function_name)
        if hasattr(args, 'script') and args.script:
            zf.write(args.script, 'init_script.sh')
            config.Lambda.lambda_env_variables['Variables']['INIT_SCRIPT_PATH'] = "/var/task/init_script.sh"
    if hasattr(args, 'extra_payload') and args.extra_payload:
        zipfolder(config.Lambda.zip_file_path, args.extra_payload)
        config.Lambda.lambda_env_variables['Variables']['EXTRA_PAYLOAD'] = "/var/task/extra/"
    # Return the zip as an array of bytes
    with open(config.Lambda.zip_file_path, 'rb') as f:
        return f.read()

def zipfolder(zipPath, target_dir):            
    with zipfile.ZipFile(zipPath, 'a', zipfile.ZIP_DEFLATED) as zf:
        rootlen = len(target_dir) + 1
        for base, _, files in os.walk(target_dir):
            for file in files:
                fn = os.path.join(base, file)
                zf.write(fn, 'extra/' + fn[rootlen:])

def set_function_attributes(args):
    for attr in args.__dict__.keys():
        config.set_attribute(config.Lambda, attr, args.__dict__[attr])

#def set_lambda_function_attribute():
    
def init(args):
    pprint.pprint(args.__dict__)
    set_function_attributes(args)
    pprint.pprint(config.Lambda.__dict__)

    '''
    # set_binary_or_container(args)
    set_function_name(args)
    validate_function_name()
    set_function_handler_name()
    set_function_description(args)
    create_code_package(args)
    check_function_existence()
    set_function_memory(args)
    set_function_running_time(args)
    set_lambda_function_role(args)
    set_function_threshold(args)
    set_recursive_property(args)
    set_environment_variables(args)
    set_function_owner()
    # Call the AWS services
    result = Result()
    function_arn = create_function(result)
    create_log_group(result)
    add_event_source(args, function_arn)
    # Show results
    result.print_results(json=args.json, verbose=args.verbose)
    # If preheat is activated, the function is launched at the init step
    preheat_function(args)
    '''

def run(args):
    # Check if function not exists
    aws_client.check_function_name_not_exists(args.name, (True if args.verbose or args.json else False))
    # Set call parameters
    set_function_invocation_type(args)
    # Modify memory if necessary
    update_function_memory( args)
    # Modify timeout if necessary
    if hasattr(args, 'time') and args.time:
        aws_client.update_function_timeout(args.name, args.time)
    # Modify environment vars if necessary
    if hasattr(args, 'env') and args.env:
        aws_client.update_function_env_variables(args.name, args.env)
    payload = {}
    # Parse the function script
    if hasattr(args, 'script') and args.script:
        payload = { "script" : scar_utils.escape_string(args.script.read()) }
    # Or parse the container arguments
    elif hasattr(args, 'cont_args') and args.cont_args:
        payload = { "cmd_args" : scar_utils.escape_list(args.cont_args) }

    # Use the event source to launch the function
    if hasattr(args, 'event_source') and args.event_source:
        log_type = 'None'
        event = config.Lambda.lambda_event
        event['Records'][0]['s3']['bucket']['name'] = args.event_source
        s3_files = aws_client.get_s3_file_list(args.event_source)
        print("Files found: '%s'" % s3_files)

        if len(s3_files) >= 1:
            aws_client.launch_request_response_event(s3_files[0], event,  args)

        if len(s3_files) > 1:
            s3_files = s3_files[1:]
            size = len(s3_files)

            chunk_size = 1000
            if size > chunk_size:
                s3_file_chunks = divide_list_in_chunks(s3_files, chunk_size)
                for s3_file_chunk in s3_file_chunks:
                    pool = ThreadPool(processes=len(s3_file_chunk))
                    pool.map(
                        lambda s3_file: aws_client.launch_async_event(s3_file, event,  args),
                        s3_file_chunk
                    )
                    pool.close()
            else:
                pool = ThreadPool(processes=len(s3_files))
                pool.map(
                    lambda s3_file: aws_client.launch_async_event(s3_file, event,  args),
                    s3_files
                )
                pool.close()
    else:
        aws_client.launch_lambda_instance( args, config.Lambda.invocation_type, config.Lambda.log_type, json.dumps(payload))
    
def ls(args):
    try:
        # Get the filtered resources from AWS
        lambda_functions = aws_client.get_all_functions()
        # Create the data structure
        functions_parsed_info = []
        functions_full_info = []
        for lambda_function in lambda_functions:
            parsed_function = {'Name' : lambda_function['Configuration']['FunctionName'],
                        'Memory' : lambda_function['Configuration']['MemorySize'],
                        'Timeout' : lambda_function['Configuration']['Timeout'],
                        'Image_id': lambda_function['Configuration']['Environment']['Variables']['IMAGE_ID']}
            functions_full_info.append(lambda_function)
            functions_parsed_info.append(parsed_function)

        result = Result()
        result.append_to_verbose('LambdaOutput', functions_full_info)
        result.append_to_json('Functions', functions_parsed_info)
        # Parse output
        if args.verbose:
            result.print_verbose_result()
        elif args.json:
            result.print_json_result()
        else:
            result.generate_table(functions_parsed_info)

    except ClientError as ce:
        print ("Error listing the resources: %s" % ce)

def set_function_invocation_type(args):
    config.Lambda.invocation_type = 'RequestResponse'
    config.Lambda.log_type = 'Tail'
    if hasattr(args, 'async') and args.async:
        config.Lambda.invocation_type = 'Event'
        config.Lambda.log_type = 'None'

def update_function_memory( args):
    set_function_memory(args)
    aws_client.update_function_memory(args.name, config.Lambda.lambda_memory)

def update(args):
    # Check if function not exists
    aws_client.check_function_name_not_exists(args.name, (True if args.verbose or args.json else False))
    # Set call parameters
    set_function_invocation_type(args)
    # Modify memory if necessary
    update_function_memory( args)
    # Modify timeout if necessary
    if hasattr(args, 'time') and args.time:
        aws_client.update_function_timeout(args.name, args.time)
    # Modify environment vars if necessary
    if hasattr(args, 'env') and args.env:
        aws_client.update_function_env_variables(args.name, args.env)
    print("Function '%s' updated successfully" % args.name)

def rm(args):
    if args.all:
        lambda_functions = aws_client.get_all_functions()
        for function in lambda_functions:
            result = aws_client.delete_resources(function['Configuration']['FunctionName'], args.json, args.verbose)
            result.print_results(args.json, args.verbose)
    else:
        result = aws_client.delete_resources(args.name, args.json, args.verbose)
        result.print_results(args.json, args.verbose)

def log(args):
    try:
        log_group_name = "/aws/lambda/%s" % args.name
        full_msg = ""
        if args.log_stream_name:
            response = aws_client.get_log().get_log_events(
                logGroupName=log_group_name,
                logStreamName=args.log_stream_name,
                startFromHead=True
            )
            for event in response['events']:
                full_msg += event['message']
        else:
            response = aws_client.get_log().filter_log_events(logGroupName=log_group_name)
            data = []

            for event in response['events']:
                data.append((event['message'], event['timestamp']))

            while(('nextToken' in response) and response['nextToken']):
                response = aws_client.get_log().filter_log_events(logGroupName=log_group_name,
                                                                             nextToken=response['nextToken'])
                for event in response['events']:
                    data.append((event['message'], event['timestamp']))

            sorted_data = sorted(data, key=lambda time: time[1])
            for sdata in sorted_data:
                full_msg += sdata[0]

        response['completeMessage'] = full_msg
        if args.request_id:
            print (parse_aws_logs(full_msg, args.request_id))
        else:
            print (full_msg)

    except ClientError as ce:
        print(ce)

def create_argparser():
    parser = command_parser.create_argparser()
    subparsers = parser.add_subparsers(title='Commands')    
    command_parser.create_init_parser(subparsers, init)
    command_parser.create_run_parser(subparsers, run)
    command_parser.create_rm_parser(subparsers, rm)
    command_parser.create_ls_parser(subparsers, ls)
    command_parser.create_log_parser(subparsers, log)
    return parser
                    
if __name__ == "__main__":
    config.check_config_file(config.Lambda)
    parser = create_argparser()
    command_parser.parse_arguments(parser)
