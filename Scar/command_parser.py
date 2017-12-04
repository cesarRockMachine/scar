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

import argparse
import logging

import Scar.scar_utils as scar_utils


def create_init_parser(subparsers, init):
    parser_init = subparsers.add_parser('init', help="Create lambda function")
    # Set default function
    parser_init.set_defaults(func=init)
    # Set the positional arguments
    parser_init.add_argument("image_id", help="Container image id (i.e. centos:7)")
    # Set the optional arguments
    parser_init.add_argument("-d", "--description", help="Lambda function description.")
    parser_init.add_argument("-e", "--environment_variables", action='append', help="Pass environment variable to the container (VAR=val). Can be defined multiple times.")
    parser_init.add_argument("-n", "--name", help="Lambda function name")
    parser_init.add_argument("-m", "--memory", type=int, help="Lambda function memory in megabytes. Range from 128 to 1536 in increments of 64")
    parser_init.add_argument("-t", "--time", type=int, help="Lambda function maximum execution time in seconds. Max 300.")
    parser_init.add_argument("-tt", "--timeout_threshold", type=int, help="Extra time used to postprocess the data. This time is extracted from the total time of the lambda function.")
    parser_init.add_argument("-j", "--json", help="Return data in JSON format", action="store_true")
    parser_init.add_argument("-v", "--verbose", help="Show the complete aws output in json format", action="store_true")
    parser_init.add_argument("-s", "--script", help="Path to the input file passed to the function")
    parser_init.add_argument("-es", "--event_source", help="Name specifying the source of the events that will launch the lambda function. Only supporting buckets right now.")
    parser_init.add_argument("-lr", "--lambda_role", help="Lambda role used in the management of the functions")
    parser_init.add_argument("-r", "--recursive", help="Launch a recursive lambda function", action="store_true")
    parser_init.add_argument("-p", "--preheat", help="Preheats the function running it once and downloading the necessary container", action="store_true")
    parser_init.add_argument("-ep", "--extra_payload", help="Folder containing files that are going to be added to the payload of the lambda function")


def create_run_parser(subparsers, run):
    parser_run = subparsers.add_parser('run', help="Deploy function")
    parser_run.set_defaults(func=run)
    parser_run.add_argument("name", help="Lambda function name")
    parser_run.add_argument("-m", "--memory", type=int, help="Lambda function memory in megabytes. Range from 128 to 1536 in increments of 64")
    parser_run.add_argument("-t", "--time", type=int, help="Lambda function maximum execution time in seconds. Max 300.")
    parser_run.add_argument("-e", "--environment_variables", action='append', help="Pass environment variable to the container (VAR=val). Can be defined multiple times.")
    parser_run.add_argument("-a", "--async", help="Tell Scar to wait or not for the lambda function return", action="store_true")
    parser_run.add_argument("-s", "--script", nargs='?', type=argparse.FileType('r'), help="Path to the input file passed to the function")
    parser_run.add_argument("-j", "--json", help="Return data in JSON format", action="store_true")
    parser_run.add_argument("-v", "--verbose", help="Show the complete aws output in json format", action="store_true")
    parser_run.add_argument("-es", "--event_source", help="Name specifying the source of the events that will launch the lambda function. Only supporting buckets right now.")
    parser_run.add_argument('cont_args', nargs=argparse.REMAINDER, help="Arguments passed to the container.")        

        
def create_rm_parser(subparsers, rm):
    parser_rm = subparsers.add_parser('rm', help="Delete function")
    parser_rm.set_defaults(func=rm)
    group = parser_rm.add_mutually_exclusive_group(required=True)
    group.add_argument("-n", "--name", help="Lambda function name")
    group.add_argument("-a", "--all", help="Delete all lambda functions", action="store_true")
    parser_rm.add_argument("-j", "--json", help="Return data in JSON format", action="store_true")
    parser_rm.add_argument("-v", "--verbose", help="Show the complete aws output in json format", action="store_true")  

                
def create_ls_parser(subparsers, ls):
    parser_ls = subparsers.add_parser('ls', help="List lambda functions")
    parser_ls.set_defaults(func=ls)
    parser_ls.add_argument("-j", "--json", help="Return data in JSON format", action="store_true")
    parser_ls.add_argument("-v", "--verbose", help="Show the complete aws output in json format", action="store_true")

        
def create_log_parser(subparsers, log):
    parser_log = subparsers.add_parser('log', help="Show the logs for the lambda function")
    parser_log.set_defaults(func=log)
    parser_log.add_argument("name", help="Lambda function name")
    parser_log.add_argument("-ls", "--log_stream_name", help="Return the output for the log stream specified.")
    parser_log.add_argument("-ri", "--request_id", help="Return the output for the request id specified.")        


def get_argparser():
    return argparse.ArgumentParser(prog="scar",
                                     description="Deploy containers in serverless architectures",
                                     epilog="Run 'scar COMMAND --help' for more information on a command.")

def parse_arguments(parser):
    try:
        """Command parsing and selection"""
        return parser.parse_args()        
    except AttributeError as ae:
        logging.error("Error parsing arguments: %s" % ae)
        print("Incorrect arguments: use scar -h to see the options available")
        scar_utils.finish_failed_execution()
        
