# #######
# Copyright (c) 2016 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.
'''
    auth.SharedKey
    ~~~~~~~~~~~~~~
    Shared Key authentication interface for the Microsoft
    Azure REST API. This interface applies for Storage API calls
'''

# Used for RFC 1123 date string
from datetime import datetime
# Used for String-to-Sign operations
import base64
import hmac
import hashlib
# For credentials structuring
from collections import namedtuple
# Exception handling, constants, logging
from cloudify_azure import \
    (constants, exceptions)
# Context
from cloudify import ctx

# pylint: disable=R0903


SharedKeyCredentials = namedtuple(
    'SharedKeyCredentials',
    ['account', 'key']
)
'''
    Microsoft Azure Shared Key credentials and access information

:param string account: Storage Account name
:param string key: Storage Account key (base64 encoded)
'''


def get_rfc1123_date():
    '''
        Azure Storage headers use RFC 1123 for date representation.
        See https://msdn.microsoft.com/en-us/library/azure/dd135714.aspx
    '''
    return datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')


class SharedKey(object):
    '''
        SharedKey interface for the Microsoft Azure REST API

    :param `SharedKeyCredentials` credentials:
        Azure Shared Key credentials and access information
    :param `logging.Logger` logger:
        Logger for the class to use. Defaults to `ctx.logger`
    '''

    def __init__(self, credentials,
                 version=constants.API_VER_STORAGE_BLOB,
                 logger=None,
                 _ctx=ctx):
        # Set the active context
        self.ctx = _ctx
        # Configure logger
        self.log = logger or ctx.logger
        # Validate credentials type
        if not isinstance(credentials, SharedKeyCredentials):
            raise exceptions.InvalidCredentials(
                'SharedKey() recieved credentials not of '
                'type SharedKeyCredentials')
        # Get user authentication data
        self.credentials = credentials
        self.version = version

    def generate(self):
        '''Generates URL and access headers'''
        return (self.generate_url(), self.generate_headers())

    def generate_url(self, base_url=constants.CONN_STORAGE_BLOB_ENDPOINT):
        '''Generates a method-specific URL'''
        return constants.CONN_STORAGE_BLOB_ENDPOINT.format(
            self.credentials.account)

    def generate_headers(self):
        '''Generates method-specific access headers'''
        rfc1123_date = get_rfc1123_date()
        return {
            'x-ms-version': self.version,
            'x-ms-date': rfc1123_date,
            'Authorization': 'SharedKey {0}:{1}'.format(
                self.credentials.account,
                base64.b64encode(hmac.new(
                    base64.b64decode(self.credentials.key),
                    'GET\n\n\n\n\n\n\n\n\n\n\n\n{0}\n{1}\n/{2}/\n{3}'.format(
                        'x-ms-date:{0}'.format(rfc1123_date),
                        'x-ms-version:{0}'.format(self.version),
                        self.credentials.account,
                        'comp:list'),
                    hashlib.sha256
                ).digest()))
        }
