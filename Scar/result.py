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
from tabulate import tabulate

class Result(object):

    def __init__(self, args):
        self.verbose = {}
        self.json = {}
        self.plain_text = ""
        self.json_output = args.json
        self.verbose_output = args.verbose

    def append_to_verbose(self, key, value):
        self.verbose[key] = value

    def append_to_json(self, key, value):
        self.json[key] = value

    def append_to_plain_text(self, value):
        self.plain_text += value + "\n"

    def print_verbose_result(self):
        print(json.dumps(self.verbose))

    def print_json_result(self):
        print(json.dumps(self.json))

    def print_plain_text_result(self):
        print(self.plain_text)

    def print_results(self):
        # Verbose output has precedence against json output
        if self.verbose_output:
            self.print_verbose_result()
        elif self.json_output:
            self.print_json_result()
        else:
            self.print_plain_text_result()

    def generate_table(self, functions_info):
        headers = ['NAME', 'MEMORY', 'TIME', 'IMAGE_ID']
        table = []
        for function in functions_info:
            table.append([function['Name'],
                          function['Memory'],
                          function['Timeout'],
                          function['Image_id']])
        print (tabulate(table, headers))

    def add_warning_message(self, message):
        self.append_to_verbose('Warning', message)
        self.append_to_json('Warning', message)
        self.append_to_plain_text ("Warning: %s" % message)
