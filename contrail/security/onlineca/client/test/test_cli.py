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
import sys
import shutil
import unittest

import six
from OpenSSL import crypto

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
                                "http://localhost:10443/certificate/")

    ONLINECA_GET_TRUSTROOTS_URL = os.environ.get(
                               "TEST_ONLINECA_GET_TRUSTROOTS_URL",
                               "http://localhost:10443/trustroots/")

    CACERT_DIR = os.path.join(TEST_DIR, "test-cli-ca")
    USERNAME = os.environ.get("TEST_ONLINECA_GET_CERT_USERNAME", "testuser")
    PASSWORD = os.environ.get("TEST_ONLINECA_GET_CERT_PASSWORD", "changeme")
    PEM_OUT_FILEPATH = os.path.join(TEST_DIR, "cli-test-usercert.pem")

    def setUp(self):
        try:
            OnlineCaClientCLI().main(
                OnlineCaClientCLI.GET_TRUSTROOTS_CMD,
                '-s', self.__class__.ONLINECA_GET_TRUSTROOTS_URL,
                '-b',
                '--ca-cert-dir', self.__class__.CACERT_DIR
            )

        except Exception:
            shutil.rmtree(self.__class__.CACERT_DIR, True)
            raise

    def tearDown(self):
        shutil.rmtree(self.__class__.CACERT_DIR, True)
        unittest.TestCase.tearDown(self)

    def _check_cert(self, cert_filepath):
        with open(cert_filepath, 'rb') as cert_file:
            s_cert = cert_file.read()

        cert = crypto.load_certificate(crypto.FILETYPE_PEM, s_cert)
        self.assertIsNotNone(cert.get_issuer())

        return cert

    def test02_get_cert(self):

        try:
            # Fake stdin for password fed in via stdin
            stdin_stream = sys.stdin
            fake_stdin = six.StringIO()

            fake_stdin.write(self.__class__.PASSWORD)
            fake_stdin.seek(0)
            sys.stdin = fake_stdin

            OnlineCaClientCLI().main(
                OnlineCaClientCLI.GET_CERT_CMD,
                '-s', self.__class__.ONLINECA_GET_CERT_URL,
                '-l', self.__class__.USERNAME,
                '--stdin-password',
                '-o', self.__class__.PEM_OUT_FILEPATH,
                '-c', self.__class__.CACERT_DIR
            )

            self._check_cert(self.__class__.PEM_OUT_FILEPATH)
        finally:
            sys.stdin = stdin_stream
            try:
                os.unlink(self.__class__.PEM_OUT_FILEPATH)
            except file_not_found_excep:
                pass


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()