#!/usr/bin/env python
"""Unit tests for Online CA Web Service client
"""
__author__ = "P J Kershaw"
__date__ = "28/05/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)
import unittest
import os
from getpass import getpass

import six

# six doesn't seem to handle SafeConfigParser deprecation correctly:
if six.PY2:
    from six.moves.configparser import SafeConfigParser as SafeConfigParser_
else:
    from six.moves.configparser import ConfigParser as SafeConfigParser_

from six.moves.configparser import NoOptionError

from OpenSSL import crypto

from contrail.security.onlineca.client import OnlineCaClient
from contrail.security.onlineca.client.test import TEST_CA_DIR, TEST_DIR

log = logging.getLogger(__name__)


class OnlineCaClientTestCase(unittest.TestCase):
    """Test OnlineCA Service Client"""
    config_filepath = os.environ.get('TEST_ONLINECA_CLIENT_CFG_FILEPATH') or \
		os.path.join(TEST_DIR, 'test_onlineca_client.cfg')

    def __init__(self, *args, **kwargs):
        self.cfg = SafeConfigParser_({'here': TEST_DIR})
        self.cfg.optionxform = str
        self.cfg.read(self.__class__.config_filepath)

        unittest.TestCase.__init__(self, *args, **kwargs)

    def test01_get_trustroots(self):
        opt_name = 'OnlineCaClientTestCase.test01_get_trustroots'
        server_url = self.cfg.get(opt_name, 'uri')

        onlineca_client = OnlineCaClient()
        onlineca_client.ca_cert_dir = TEST_CA_DIR

        trustroots = onlineca_client.get_trustroots(server_url, bootstrap=True,
        											write_to_ca_cert_dir=True)
        self.assert_(trustroots)
        for i in trustroots.items():
            log.info("%s:\n%s" % i)

    def test02_get_certificate(self):
        opt_name = 'OnlineCaClientTestCase.test02_get_certificate'
        username = self.cfg.get(opt_name, 'username')
        pem_out_filepath = self.cfg.get(opt_name, 'pem_out_filepath')

        try:
            password = self.cfg.get(opt_name, 'password')
        except NoOptionError:
            password = getpass('OnlineCaClientTestCase.test02_get_certificate password: ')

        server_url = self.cfg.get(opt_name, 'uri')

        onlineca_client = OnlineCaClient()
        onlineca_client.ca_cert_dir = TEST_CA_DIR

        key_pair, certs = onlineca_client.get_certificate(username, password,
                                server_url, pem_out_filepath=pem_out_filepath)
        self.assert_(key_pair)
        self.assert_(certs[0])

        subj = certs[0].get_subject()
        self.assert_(subj)
        self.assert_(subj.CN)

        log.info("Returned key pair\n%r",
						crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair))
        log.info("Returned certificate subject %r", subj)
        log.info("Returned certificate issuer %r", certs[0].get_issuer())


if __name__ == "__main__":
    unittest.main()
