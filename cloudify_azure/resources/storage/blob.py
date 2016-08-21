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
    resources.storage.Blob
    ~~~~~~~~~~~~~~~~~~~~~~
    Microsoft Azure Storage Blob interface
'''

# HTTP requests
import requests
# HTTP status codes
import httplib
# Name generation
import random
import string
# Calculating String-to-Sign operations
import base64
import hmac
import hashlib
# XML to dict
import xmltodict
# SharedKeyCredentials
from collections import namedtuple
# Node properties and logger
from cloudify import ctx
# Exception handling
from cloudify.exceptions import RecoverableError, NonRecoverableError
# Storage Account resource class
from cloudify_azure.resources.storage.storageaccount import StorageAccount
# Lifecycle operation decorator
from cloudify.decorators import operation
# Logger, API version
from cloudify_azure import (constants, utils)


SharedKeyCredentials = namedtuple(
    'SharedKeyCredentials',
    ['account', 'key']
)


def blob_name_generator():
    '''Generates a unique Blob resource name'''
    return ''.join(random.choice(string.lowercase) for i in range(15))


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
        # Validate credentials type
        if not isinstance(credentials, SharedKeyCredentials):
            return
        # Get user authentication data
        self.credentials = credentials
        self.version = version
        self.ctx = _ctx
        self.log = logger or self.ctx.logger

    def generate(self, method='get', url=None, params=None):
        '''Generates URL and access headers'''
        return (self.generate_url(url),
                self.generate_headers(method, url, params))

    def generate_url(self, url=None):
        '''Generates a method-specific URL'''
        self.log.debug('SharedKey:generate_url:url: {0}'.format(url))
        self.log.debug('SharedKey:generate_url:account: {0}'
                       .format(self.credentials.account))
        if url:
            return constants.CONN_STORAGE_BLOB_ENDPOINT.format(
                self.credentials.account) + '/{0}'.format(url)
        return constants.CONN_STORAGE_BLOB_ENDPOINT.format(
            self.credentials.account)

    def generate_headers(self, method='get', url=None,
                         headers=None, params=None):
        '''Generates method-specific access headers'''
        method = method.upper()
        rfc1123_date = utils.get_rfc1123_date()
        headers = utils.dict_update({
            'x-ms-date': rfc1123_date,
            'x-ms-version': self.version
        }, headers or dict())
        # Create the header strings
        oheaders = list()
        for key, val in sorted(headers.items()):
            oheaders.append('{0}:{1}'.format(key, val))
        # Create the parameter strings
        oparams = list()
        if params:
            for key, val in sorted(params.items()):
                oparams.append('{0}:{1}'.format(key, val))
        sas = '{0}\n\n\n\n\n\n\n\n\n\n\n\n{1}\n/{2}{3}'.format(
            method,
            '\n'.join(oheaders),
            '{0}/{1}'.format(self.credentials.account, url),
            '{0}{1}'.format(
                '\n' if params else '',
                '\n'.join(oparams)))
        self.log.debug('SAS: {0}'.format(sas))
        return utils.dict_update({
            'Authorization': 'SharedKey {0}:{1}'.format(
                self.credentials.account,
                base64.b64encode(hmac.new(
                    base64.b64decode(self.credentials.key),
                    sas,
                    hashlib.sha256
                ).digest()))
        }, headers)


class BlobContainer(object):
    '''
        Microsoft Azure Storage Blob Container interface

    .. warning::
        This interface should only be instantiated from
        within a Cloudify Lifecycle Operation

    :param string api_version: API version to use for all requests
    :param `logging.Logger` logger:
        Parent logger for the class to use. Defaults to `ctx.logger`
    '''
    def __init__(self,
                 api_version=constants.API_VER_STORAGE_BLOB,
                 logger=None,
                 _ctx=ctx):
        self.ctx = _ctx
        self.log = logger or self.ctx.logger
        storage_account = utils.get_parent(
            self.ctx.instance,
            rel_type=constants.REL_CONTAINED_IN_SA)
        # Get the storage account keys
        keys = StorageAccount(_ctx=storage_account).list_keys()
        if not isinstance(keys, list) or len(keys) < 1:
            raise RecoverableError(
                'StorageAccount reported no usable authentication keys')
        self.skey = SharedKey(
            SharedKeyCredentials(
                account=utils.get_resource_name(_ctx=storage_account),
                key=keys[0].get('key')),
            version=api_version)

    def list_blobs(self, name, params=None):
        '''
            Lists blobs in a specified container

        :param string name: Name of the container to use
        :param dict params: URI Parameters as specified in
            https://msdn.microsoft.com/en-us/library/azure/dd135734.aspx
        '''
        params = utils.dict_update({
            'comp': 'list',
            'restype': 'container'
        }, params)
        res = requests.request(**{
            'method': 'get',
            'url': self.skey.generate_url(url=name),
            'headers': self.skey.generate_headers(
                url=name,
                method='get',
                params=params),
            'params': params
        })
        return xmltodict.parse(res.text).get(
            'EnumerationResults', dict()).get(
                'Blobs', dict()).get(
                    'Blob', list())

    def exists(self, name):
        '''Checks if a container exists'''
        params = {
            'restype': 'container'
        }
        req = {
            'method': 'head',
            'url': self.skey.generate_url(url=name),
            'headers': self.skey.generate_headers(
                url=name,
                method='head',
                params=params),
            'params': params
        }
        self.log.debug('Container:exists:req: {0}'.format(req))
        res = requests.request(**req)
        self.log.debug('Container:exists:res.status_code: {0}'
                       .format(res.status_code))
        self.log.debug('Container:exists:res.headers: {0}'
                       .format(res.headers))
        self.log.debug('Container:exists:res.text: {0}'
                       .format(res.text))
        if not res.status_code == httplib.OK and \
           not res.status_code == httplib.NOT_FOUND:
            raise RecoverableError(
                'Unexpected HTTP status code returned')
        if res.status_code == httplib.NOT_FOUND:
            return False
        return True

    def create(self, name, headers=None, params=None):
        '''Create a blob in a container'''
        params = utils.dict_update({
            'restype': 'container'
        }, params or dict())
        req = {
            'method': 'put',
            'url': self.skey.generate_url(url=name),
            'headers': self.skey.generate_headers(
                url=name,
                method='put',
                headers=headers,
                params=params),
            'params': params
        }
        self.log.debug('Container:create:req: {0}'.format(req))
        res = requests.request(**req)
        self.log.debug('Container:create:res.status_code: {0}'
                       .format(res.status_code))
        self.log.debug('Container:create:res.headers: {0}'
                       .format(res.headers))
        self.log.debug('Container:create:res.text: {0}'
                       .format(res.text))
        if not res.status_code == httplib.CREATED:
            raise RecoverableError(
                'Unexpected HTTP status code returned')
        return res.headers


class Blob(object):
    '''
        Microsoft Azure Storage Blob interface

    .. warning::
        This interface should only be instantiated from
        within a Cloudify Lifecycle Operation

    :param string storage_account: Name of the parent Storage Account
    :param string api_version: API version to use for all requests
    :param `logging.Logger` logger:
        Parent logger for the class to use. Defaults to `ctx.logger`
    '''
    def __init__(self, container,
                 api_version=constants.API_VER_STORAGE_BLOB,
                 logger=None,
                 _ctx=ctx):
        self.ctx = _ctx
        self.log = logger or self.ctx.logger
        storage_account = utils.get_parent(
            self.ctx.instance,
            rel_type=constants.REL_CONTAINED_IN_SA)
        self.container = container
        # Get the storage account keys
        keys = StorageAccount(_ctx=storage_account).list_keys()
        self.log.debug('keys: ({0}) {1}'.format(type(keys), keys))
        if not isinstance(keys, list) or len(keys) < 1:
            raise RecoverableError(
                'StorageAccount reported no usable authentication keys')
        self.skey = SharedKey(
            SharedKeyCredentials(
                account=utils.get_resource_name(_ctx=storage_account),
                key=keys[0].get('key')),
            version=api_version)

    def exists(self, name):
        '''Checks if a blob exists'''
        url = '{0}/{1}'.format(self.container, name)
        req = {
            'method': 'head',
            'url': self.skey.generate_url(url=url),
            'headers': self.skey.generate_headers(
                url=url,
                method='head')
        }
        self.log.debug('Blob:exists:req: {0}'.format(req))
        res = requests.request(**req)
        self.log.debug('Blob:exists:res.status_code: {0}'
                       .format(res.status_code))
        self.log.debug('Blob:exists:res.headers: {0}'
                       .format(res.headers))
        self.log.debug('Blob:exists:res.text: {0}'
                       .format(res.text))
        if not res.status_code == httplib.OK and \
           not res.status_code == httplib.NOT_FOUND:
            raise RecoverableError(
                'Unexpected HTTP status code returned')
        if res.status_code == httplib.NOT_FOUND:
            return False
        return True

    def create(self, name, headers=None, params=None):
        '''Create a blob in a container'''
        url = '{0}/{1}'.format(self.container, name)
        req = {
            'method': 'put',
            'url': self.skey.generate_url(url=url),
            'headers': self.skey.generate_headers(
                url=url,
                method='put',
                headers=headers,
                params=params)
        }
        self.log.debug('Blob:create:req: {0}'.format(req))
        res = requests.request(**req)
        self.log.debug('Blob:create:res.status_code: {0}'
                       .format(res.status_code))
        self.log.debug('Blob:create:res.headers: {0}'
                       .format(res.headers))
        self.log.debug('Blob:create:res.text: {0}'
                       .format(res.text))
        if not res.status_code == httplib.CREATED:
            raise RecoverableError(
                'Unexpected HTTP status code returned')
        return res.headers

    def get(self, name):
        '''Get a blob in a container'''
        url = '{0}/{1}'.format(self.container, name)
        req = {
            'method': 'head',
            'url': self.skey.generate_url(url=url),
            'headers': self.skey.generate_headers(
                url=url,
                method='head')
        }
        self.log.debug('Blob:get:req: {0}'.format(req))
        res = requests.request(**req)
        self.log.debug('Blob:get:res.status_code: {0}'
                       .format(res.status_code))
        self.log.debug('Blob:get:res.headers: {0}'
                       .format(res.headers))
        self.log.debug('Blob:get:res.text: {0}'
                       .format(res.text))
        return res.headers

    def delete(self, name):
        '''Delete a blob in a container'''
        if not self.container:
            self.log.warn('Refusing to delete a Blob without '
                          'a Container specified')
            return
        if not name:
            self.log.warn('Refusing to delete a Blob without '
                          'a resource name specified')
            return
        url = '{0}/{1}'.format(self.container, name)
        req = {
            'method': 'delete',
            'url': self.skey.generate_url(url=url),
            'headers': self.skey.generate_headers(
                url=url,
                method='delete')
        }
        self.log.debug('Blob:delete:req: {0}'.format(req))
        res = requests.request(**req)
        self.log.debug('Blob:delete:res.status_code: {0}'
                       .format(res.status_code))
        self.log.debug('Blob:delete:res.headers: {0}'
                       .format(res.headers))
        self.log.debug('Blob:delete:res.text: {0}'
                       .format(res.text))
        if not res.status_code == httplib.ACCEPTED:
            raise RecoverableError(
                'Unexpected HTTP status code returned')
        return res.headers


@operation
def create_disk(**_):
    '''Uses an existing, or creates a new, Disk'''
    if ctx.node.properties.get('use_external_resource', False) and \
       not ctx.node.properties.get('name'):
        raise NonRecoverableError(
            '"use_external_resource" specified without a resource "name"')
    # Create the blob container (if needed)
    container_name = 'vhds'
    container_iface = BlobContainer()
    if not container_iface.exists(container_name):
        container_iface.create(container_name)
    # Generate a resource name (if needed)
    blob_iface = Blob(container=container_name)
    name = utils.generate_resource_name(
        blob_iface,
        generator=blob_name_generator)
    vhd_name = name + '.vhd'
    ctx.logger.debug('Disk name: {0}'.format(vhd_name))
    # Create the resource
    if not ctx.node.properties.get('use_external_resource', False):
        if not ctx.node.properties.get('disk_size'):
            raise NonRecoverableError(
                '"disk_size" property must be set')
        disk_size = ctx.node.properties['disk_size'] * (1024*1024*1024)
        blob_iface.create(vhd_name, headers={
            'x-ms-blob-type': 'PageBlob',
            'x-ms-blob-content-length': '{0}'.format(disk_size)
        })
    # Set the runtime properties
    ctx.instance.runtime_properties['uri'] = \
        blob_iface.skey.generate_url(
            url='{0}/{1}'.format(container_name, vhd_name))


@operation
def delete_disk(**_):
    '''Deletes a Disk'''
    # Delete the resource
    if not ctx.node.properties.get('use_external_resource', False):
        Blob(container='vhds').delete(name=utils.get_resource_name() + '.vhd')
