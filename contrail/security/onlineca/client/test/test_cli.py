"""Online CA service client - command line client unit tests

Contrail Project
"""
__author__ = "P J Kershaw"
__date__ = "28/05/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import os
import unittest

import six

from contrail.security.onlineca.client.test import TEST_DIR
from contrail.security.onlineca.client.cli import OnlineCaClientCLI

if six.PY2:
    # Workaround for FileNotFoundError.  IOError is more generic but the
    # match is sufficient for the purposes of these tests
    file_not_found_excep = OSError
else:
    # Compatibility wrapper to allow dual Python 2/3 support
    file_not_found_excep = FileNotFoundError


class OnlineCaClientCLITestCase(unittest.TestCase):
    'Test Certificate Authority command line interface'
    ONLINECA_GET_CERT_URL = os.environ.get(
                                "TEST_ONLINECA_GET_CERT_URL",
                                "https://localhost:5000/oauth/certificate/")

    ONLINECA_GET_TRUSTROOTS_URL = os.environ.get(
                                   "TEST_ONLINECA_GET_TRUSTROOTS_URL",
                                   "https://localhost:5000/oauth/trustroots")

    CACERT_DIR = os.path.join(TEST_DIR, "test-cli-ca")
    USERNAME = ""
    PEM_OUT_FILEPATH = os.path.join(TEST_DIR, "cli-test-usercert.pem")

    def test01_get_trustroots_with_bootstrap(self):
        try:
            OnlineCaClientCLI().main(
                OnlineCaClientCLI.GET_TRUSTROOTS_CMD,
                '-s', self.__class__.ONLINECA_GET_TRUSTROOTS_URL,
                '-b',
                '--ca-cert-dir', self.__class__.CACERT_DIR
            )

        finally:
            try:
                os.unlink(self.__class__.CACERT_DIR)
            except file_not_found_excep:
                pass

    def test02_get_cert_with_bootstrap(self):
        try:
            OnlineCaClientCLI().main(
                OnlineCaClientCLI.GET_CERT_CMD,
                '-s', self.__class__.ONLINECA_GET_CERT_URL,
                '-l', self.__class__.USERNAME,
                '-o', self.__class__.PEM_OUT_FILEPATH,
                '-b'
            )

            self._check_cert(self.__class__.PEM_OUT_FILEPATH)
        finally:
            try:
                os.unlink(self.__class__.PEM_OUT_FILEPATH)
            except file_not_found_excep:
                pass


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()