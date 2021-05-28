#!/usr/bin/env python3
#
# Copyright 2021 Venafi, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from ansible.module_utils.basic import AnsibleModule

from vcert import Connection, venafi_connection


class Venafi:
    def __init__(self, module):
        """
        :param AnsibleModule module:
        """
        self.test_mode = module.params['test_mode']
        self.url = module.params['url']
        self.user = module.params['user']
        self.password = module.params['password']
        self.access_token = module.params['access_token']
        self.apikey = module.params['token']

        if self.user != "":
            module.warn("User is deprecated use access token instead")
        if self.password != "":
            module.warn("Password is deprecated use access token instead")

        trust_bundle = module.params['trust_bundle']
        # Legacy Connection. Deprecated. Do not use
        if self.user and self.password:
            self.connection = Connection(
                url=self.url, user=self.user, password=self.password,
                http_request_kwargs=(
                    {"verify": trust_bundle} if trust_bundle else None
                ),
                fake=self.test_mode,
            )
        else:
            self.connection = venafi_connection(
                url=self.url, access_token=self.access_token, api_key=self.apikey,
                http_request_kwargs=(
                    {"verify": trust_bundle} if trust_bundle else None
                ),
                fake=self.test_mode
            )
