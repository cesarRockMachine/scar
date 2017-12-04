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
import logging
import uuid

from Scar.aws_lambda import OutputType
import Scar.scar_utils as scar_utils


class AWSClient(object):
    
    def __init__(self):
        # Default values
        self.botocore_client_read_timeout = 360
        self.default_aws_region = "us-east-1"
    
    def create_function_name(self, image_id_or_path):
        parsed_id_or_path = image_id_or_path.replace('/', ',,,').replace(':', ',,,').replace('.', ',,,').split(',,,')
        name = 'scar-%s' % '-'.join(parsed_id_or_path)
        i = 1
        while self.find_function_name(name):
            name = 'scar-%s-%s' % ('-'.join(parsed_id_or_path), str(i))
            i = i + 1
        return name
    
    def check_memory(self, lambda_memory):
        """ Check if the memory introduced by the user is correct.
        If the memory is not specified in 64mb increments,
        transforms the request to the next available increment."""
        if (lambda_memory < 128) or (lambda_memory > 1536):
            raise Exception('Incorrect memory size specified\nPlease, set a value between 128 and 1536.')
        else:
            res = lambda_memory % 64
            if (res == 0):
                return lambda_memory
            else:
                return lambda_memory - res + 64
    
    def check_time(self, lambda_time):
        if (lambda_time <= 0) or (lambda_time > 300):
            raise Exception('Incorrect time specified\nPlease, set a value between 0 and 300.')
        return lambda_time
    
    def get_user_name_or_id(self):
        try:
            user = self.get_iam().get_user()['User']
            return user.get('UserName', user['UserId'])
        except ClientError as ce:
            # If the user doesn't have access rights to IAM
            return scar_utils.find_expression('(?<=user\/)(\S+)', str(ce))
    
    def get_access_key(self):
        session = boto3.Session()
        credentials = session.get_credentials()
        return credentials.access_key
    
    def get_boto3_client(self, client_name, region=None):
        if region is None:
            region = self.default_aws_region
        boto_config = botocore.config.Config(read_timeout=self.botocore_client_read_timeout)            
        return boto3.client(client_name, region_name=region, config=boto_config)
    
    def get_lambda(self, region=None):
        return self.get_boto3_client('lambda', region)
    
    def get_log(self, region=None):
        return self.get_boto3_client('logs', region)
    
    def get_iam(self, region=None):
        return self.get_boto3_client('iam', region)
    
    def get_resource_groups_tagging_api(self, region=None):
        return self.get_boto3_client('resourcegroupstaggingapi', region)
    
    def get_s3(self, region=None):
        return self.get_boto3_client('s3', region)
    
    def get_s3_file_list(self, bucket_name):
        file_list = []
        result = self.get_s3().list_objects_v2(Bucket=bucket_name, Prefix='input/')
        if 'Contents' in result:
            for content in result['Contents']:
                if content['Key'] and content['Key'] != "input/":
                    file_list.append(content['Key'])
        return file_list
    
    def find_function_name(self, function_name):
        try:
            paginator = self.get_lambda().get_paginator('list_functions')
            for functions in paginator.paginate():
                for lfunction in functions['Functions']:
                    if function_name == lfunction['FunctionName']:
                        return True
            return False
        except ClientError as ce:
            print("Error listing the lambda functions")
            logging.error("Error listing the lambda functions: %s" % ce)
            scar_utils.finish_failed_execution()
    
    def check_function_name_not_exists(self, function_name):
        if not self.find_function_name(function_name):
            print("Function '%s' doesn't exist." % function_name)
            logging.error("Function '%s' doesn't exist." % function_name)
            scar_utils.finish_failed_execution()
    
    def check_function_name_exists(self, function_name):
        if self.find_function_name(function_name):
            print("Function name '%s' already used." % function_name)
            logging.error ("Function name '%s' already used." % function_name)
            scar_utils.finish_failed_execution()
    
    def update_function_timeout(self, function_name, timeout):
        try:
            self.get_lambda().update_function_configuration(FunctionName=function_name,
                                                                   Timeout=self.check_time(timeout))
        except ClientError as ce:
            print("Error updating lambda function timeout")
            logging.error("Error updating lambda function timeout: %s" % ce)
    
    def update_function_memory(self, function_name, memory):
        try:
            self.get_lambda().update_function_configuration(FunctionName=function_name,
                                                                   MemorySize=memory)
        except ClientError as ce:
            print("Error updating lambda function memory")
            logging.error("Error updating lambda function memory: %s" % ce)
    
    def create_function(self, aws_lambda): 
        try:
            logging.info("Creating lambda function.")
            response = self.get_lambda().create_function(FunctionName=aws_lambda.name,
                                                     Runtime=aws_lambda.runtime,
                                                     Role=aws_lambda.role,
                                                     Handler=aws_lambda.handler,
                                                     Code=aws_lambda.code,
                                                     Environment=aws_lambda.environment,
                                                     Description=aws_lambda.description,
                                                     Timeout=aws_lambda.time,
                                                     MemorySize=aws_lambda.memory,
                                                     Tags=aws_lambda.tags)
            aws_lambda.function_arn = response['FunctionArn']
            return response
        except ClientError as ce:
            print("Error creating lambda function")
            logging.error("Error creating lambda function: %s" % ce)        
        
    def create_log_group(self, aws_lambda):
        try:
            logging.info("Creating cloudwatch log group.")
            return self.get_log().create_log_group(logGroupName=aws_lambda.log_group_name,
                                                   tags=aws_lambda.tags)
        except ClientError as ce:
            if ce.response['Error']['Code'] == 'ResourceAlreadyExistsException':
                print("Using existent log group '%s'" % aws_lambda.log_group_name)
                logging.warning("Using existent log group '%s'" % aws_lambda.log_group_name)
                pass
            else:
                logging.error("Error creating log groups: %s" % ce)   
                scar_utils.finish_failed_execution() 
    
    def set_log_retention_policy(self, aws_lambda):
        try:
            logging.info("Setting log group policy.")
            self.get_log().put_retention_policy(logGroupName=aws_lambda.log_group_name,
                                           retentionInDays=aws_lambda.log_retention_policy_in_days)
        except ClientError as ce:
            print("Error setting log retention policy")
            logging.error("Error setting log retention policy: %s" % ce)    
    
    def get_function_environment_variables(self, function_name):
        return self.get_lambda().get_function(FunctionName=function_name)['Configuration']['Environment']
    
    def update_function_env_variables(self, function_name, env_vars):
        try:
            # Retrieve the global variables already defined
            lambda_env_variables = self.get_function_environment_variables(function_name)
            self.parse_environment_variables(lambda_env_variables, env_vars)
            self.get_lambda().update_function_configuration(FunctionName=function_name,
                                                                    Environment=lambda_env_variables)
        except ClientError as ce:
            print("Error updating the environment variables of the lambda function")
            logging.error("Error updating the environment variables of the lambda function: %s" % ce)
    
    def get_trigger_configuration(self, function_arn, folder_name):
        return { "LambdaFunctionArn": function_arn,
                 "Events": [ "s3:ObjectCreated:*" ],
                 "Filter": { 
                     "Key": { 
                         "FilterRules": [
                             { "Name": "prefix",
                               "Value": folder_name }
                         ]
                     }
                 }}
    
    def put_bucket_notification_configuration(self, bucket_name, notification):
        try:
            self.get_s3().put_bucket_notification_configuration(Bucket=bucket_name,
                                                                NotificationConfiguration=notification)
        except ClientError as ce:
            print("Error configuring S3 bucket")
            logging.error("Error configuring S3 bucket: %s" % ce)
        
    def create_trigger_from_bucket(self, bucket_name, function_arn):
        notification = { "LambdaFunctionConfigurations": [self.get_trigger_configuration(function_arn, "input/")] }
        self.put_bucket_notification_configuration(bucket_name, notification)
            
    def create_recursive_trigger_from_bucket(self, bucket_name, function_arn):
        notification = { "LambdaFunctionConfigurations": [
                            self.get_trigger_configuration(function_arn, "input/"),
                            self.get_trigger_configuration(function_arn, "recursive/")] }
        self.put_bucket_notification_configuration(bucket_name, notification)          
    
    def add_lambda_permissions(self, lambda_name, bucket_name):
        try:
            self.get_lambda().add_permission(FunctionName=lambda_name,
                                             StatementId=str(uuid.uuid4()),
                                             Action="lambda:InvokeFunction",
                                             Principal="s3.amazonaws.com",
                                             SourceArn='arn:aws:s3:::%s' % bucket_name
                                            )
        except ClientError as ce:
            print("Error setting lambda permissions")
            logging.error("Error setting lambda permissions: %s" % ce)
    
    def check_and_create_s3_bucket(self, bucket_name):
        try:
            buckets = self.get_s3().list_buckets()
            # Search for the bucket
            found_bucket = [bucket for bucket in buckets['Buckets'] if bucket['Name'] == bucket_name]
            if not found_bucket:
                # Create the bucket if not found
                self.create_s3_bucket(bucket_name)
            # Add folder structure
            self.add_s3_bucket_folder(bucket_name, "input/")
            self.add_s3_bucket_folder(bucket_name, "output/")
        except ClientError as ce:
            print("Error getting the S3 buckets list")
            logging.error("Error getting the S3 buckets list: %s" % ce)
    
    def create_s3_bucket(self, bucket_name):
        try:
            self.get_s3().create_bucket(ACL='private', Bucket=bucket_name)
        except ClientError as ce:
            print("Error creating the S3 bucket '%s'" % bucket_name)
            logging.error("Error creating the S3 bucket '%s': %s" % (bucket_name, ce))
    
    def add_s3_bucket_folder(self, bucket_name, folder_name):
        try:
            self.get_s3().put_object(Bucket=bucket_name, Key=folder_name)
        except ClientError as ce:
            print("Error creating the S3 bucket '%s' folder '%s'" % (bucket_name, folder_name))
            logging.error("Error creating the S3 bucket '%s' folder '%s': %s" % (bucket_name, folder_name, ce))
    
    def get_functions_arn_list(self):
        arn_list = []
        try:
            # Creation of a function filter by tags
            client = self.get_resource_groups_tagging_api()
            tag_filters = [ { 'Key': 'owner', 'Values': [ self.get_user_name_or_id() ] },
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
            print("Error getting function arn by tag")
            logging.error("Error getting function arn by tag: %s" % ce)
        return arn_list
    
    def get_function_info_by_arn(self, function_arn):
        try:
            return self.get_lambda().get_function(FunctionName=function_arn)
        except ClientError as ce:
            print("Error getting function info by arn")
            logging.error("Error getting function info by arn: %s" % ce)
    
    def get_all_functions(self):
        function_list = []
        # Get the filtered resources from AWS
        function_arn_list = self.get_functions_arn_list()
        try:
            for function_arn in function_arn_list:
                function_info = self.get_function_info_by_arn(function_arn)
                function_list.append(function_info)
        except ClientError as ce:
            print("Error getting all functions")
            logging.error("Error getting all functions: %s" % ce)
        return function_list
    
    def delete_lambda_function(self, function_name):
        try:
            # Delete the lambda function
            return self.get_lambda().delete_function(FunctionName=function_name)
        except ClientError as ce:
            print("Error deleting the lambda function")
            logging.error("Error deleting the lambda function: %s" % ce)
    
    def delete_cloudwatch_group(self, function_name):
        try:
            # Delete the cloudwatch log group
            log_group_name = '/aws/lambda/%s' % function_name
            return self.get_log().delete_log_group(logGroupName=log_group_name)
        except ClientError as ce:
            if ce.response['Error']['Code'] == 'ResourceNotFoundException':
                print("Cannot delete log group '%s'. Group not found." % log_group_name)
                logging.warning("Cannot delete log group '%s'. Group not found." % log_group_name)
            else:
                print("Error deleting the cloudwatch log")
                logging.error("Error deleting the cloudwatch log: %s" % ce)

    def delete_all_resources(self, aws_lambda):
        lambda_functions = self.get_all_functions()
        for function in lambda_functions:
            self.delete_resources(function['Configuration']['FunctionName'], aws_lambda.output)
    
    def parse_delete_function_response(self, function_name, reponse, output_type):
        if output_type == OutputType.VERBOSE:
            logging.info('LambdaOutput', reponse)
        elif output_type == OutputType.JSON:            
            logging.info('LambdaOutput', { 'RequestId' : reponse['ResponseMetadata']['RequestId'],
                                         'HTTPStatusCode' : reponse['ResponseMetadata']['HTTPStatusCode'] })
        else:
            logging.info("Function '%s' successfully deleted." % function_name)
        print("Function '%s' successfully deleted." % function_name)                 
    
    def parse_delete_log_response(self, function_name, response, output_type):
        if response:
            log_group_name = '/aws/lambda/%s' % function_name
            if output_type == OutputType.VERBOSE:
                logging.info('CloudWatchOutput', response)
            elif output_type == OutputType.JSON:            
                logging.info('CloudWatchOutput', { 'RequestId' : response['ResponseMetadata']['RequestId'],
                                                                   'HTTPStatusCode' : response['ResponseMetadata']['HTTPStatusCode'] })
            else:
                logging.info("Log group '%s' successfully deleted." % log_group_name)
            print("Log group '%s' successfully deleted." % log_group_name)
    
    def delete_resources(self, function_name, output_type):
        self.check_function_name_not_exists(function_name)
        delete_function_response = self.delete_lambda_function(function_name)
        self.parse_delete_function_response(function_name, delete_function_response, output_type)
        delete_log_response = self.delete_cloudwatch_group(function_name)
        self.parse_delete_log_response(function_name, delete_log_response, output_type)
    
    def launch_async_event(self, aws_lambda, s3_file):
        aws_lambda.set_asynchronous_call_parameters()
        return self.launch_s3_event(aws_lambda, s3_file)        
   
    def launch_request_response_event(self, aws_lambda, s3_file):
        aws_lambda.set_request_response_call_parameters()
        return self.launch_s3_event(aws_lambda, s3_file)            

    def preheat_function(self, aws_lambda):
        aws_lambda.set_request_response_call_parameters()
        return self.invoke_lambda_function(aws_lambda)
                
    def launch_s3_event(self, aws_lambda, s3_file):
        aws_lambda.set_event_source_file_name(s3_file)
        aws_lambda.set_payload(aws_lambda.event)
        logging.info("Sending event for file '%s'" % s3_file)
        self.invoke_lambda_function(aws_lambda)   
        
    def invoke_lambda_function(self, aws_lambda):
        response = {}
        try:
            response = self.get_lambda().invoke(FunctionName=aws_lambda.name,
                                                InvocationType=aws_lambda.invocation_type,
                                                LogType=aws_lambda.log_type,
                                                Payload=aws_lambda.payload)
        except ClientError as ce:
            print("Error invoking lambda function")
            logging.error("Error invoking lambda function: %s" % ce)
            scar_utils.finish_failed_execution()
    
        except ReadTimeout as rt:
            print("Timeout reading connection pool")
            logging.error("Timeout reading connection pool: %s" % rt)
            scar_utils.finish_failed_execution()
        return response    

