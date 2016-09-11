'''
    lifecycle.Configure
    ~~~~~~~~~~~~~~~~~~~
    Test application for grid compute
'''

import requests
from cloudify import ctx
from cloudify.exceptions import RecoverableError


def main():
    '''Entry point'''
    uri = 'http://canihazip.com/s'
    ctx.logger.info('Getting our public IP from CanIHazIP.com')
    ctx.logger.debug('GET %s' % uri)
    res = requests.get(uri)
    ctx.logger.debug('Response: HTTP %s (text=%s)' % (
        res.status_code, res.text))
    if res.status_code != 200:
        raise RecoverableError(
            'Error getting our public IP (status=%s)' % res.status_code)
    ctx.logger.info('Our public IP is "%s"' % res.text)

main()
