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

import configparser
import os
import Scar.scar_utils as scar_utils

class Lambda(object):
#    is_binary = False
#    is_container = False
    invocation_type = ""
    log_type = ""    
    code = ""
    name = ""
    runtime = "python3.6"
    handler = name + ".lambda_handler"
    role = ""
    region = 'us-east-1'
    env_variables = {"Variables" : {"UDOCKER_DIR":"/tmp/home/.udocker",
                                           "UDOCKER_TARBALL":"/var/task/udocker-1.1.0-RC2.tar.gz"}}
    memory = 128
    time = 300
    timeout_threshold = 10
    description = "Automatically generated lambda function"
    tags = { 'createdby' : 'scar' }
    event = { "Records" : [
                        { "eventSource" : "aws:s3",
                          "s3" : {
                              "bucket" : {
                                  "name" : ""},
                              "object" : {
                                  "key" : "" }
                            }
                        }
                    ]}
    dir_path = os.path.abspath(os.curdir)
    zip_file_path = dir_path + '/function.zip'
    config_parser = configparser.ConfigParser()

def set_attribute(lambda_config, attr, value):
    setattr(lambda_config, attr, value)

def create_config_file(lambda_config, file_dir):
    lambda_config.config_parser['scar'] = {'lambda_description' : "Automatically generated lambda function",
                      'lambda_memory' : lambda_config.memory,
                      'lambda_time' : lambda_config.time,
                      'lambda_region' : 'us-east-1',
                      'lambda_role' : '',
                      'lambda_timeout_threshold' : lambda_config.timeout_threshold}
    with open(file_dir + "/scar.cfg", "w") as configfile:
        lambda_config.config_parser.write(configfile)

    print ("Config file %s/scar.cfg created.\nPlease, set first a valid lambda role to be used." % file_dir)
    scar_utils.force_finish_successful_execution()

def check_config_file(lambda_config):
    scar_dir = os.path.expanduser("~") + "/.scar"
    # Check if the scar directory exists
    if os.path.isdir(scar_dir):
        # Check if the config file exists
        if os.path.isfile(scar_dir + "/scar.cfg"):
            lambda_config.config_parser.read(scar_dir + "/scar.cfg")
            parse_config_file_values(lambda_config)
        else:
            create_config_file(lambda_config, scar_dir)
    else:
        # Create scar dir
        os.makedirs(scar_dir)
        create_config_file(lambda_config,scar_dir)

def parse_config_file_values(lambda_config):
    scar_config = lambda_config.config_parser['scar']
    lambda_config.role = scar_config.get('lambda_role', fallback=lambda_config.role)
    if not lambda_config.role or lambda_config.role == "":
        print ("Please, specify first a lambda role in the ~/.scar/scar.cfg file.")
        scar_utils.force_finish_failed_execution()
    lambda_config.region = scar_config.get('lambda_region', fallback=lambda_config.region)
    lambda_config.memory = scar_config.getint('lambda_memory', fallback=lambda_config.memory)
    lambda_config.time = scar_config.getint('lambda_time', fallback=lambda_config.time)
    lambda_config.description = scar_config.get('lambda_description', fallback=lambda_config.description)
    lambda_config.timeout_threshold = scar_config.get('lambda_timeout_threshold', fallback=lambda_config.timeout_threshold)
    