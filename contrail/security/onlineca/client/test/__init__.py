#!/usr/bin/env python
"""Package for tests for Online CA web service client 
functionality
"""
__author__ = "P J Kershaw"
__date__ = "22/08/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import os

TEST_DIR = os.path.dirname(__file__)
ONLINECA_CLIENT_PKG_DIR = os.path.dirname(TEST_DIR)
TEST_CA_DIR = os.path.join(TEST_DIR, 'ca')
CLIENT_SHELL_SCRIPTS_DIR = os.path.join(ONLINECA_CLIENT_PKG_DIR, 'sh')
GET_CERT_SHELL_SCRIPT = 'onlineca-get-cert.sh'
GET_TRUSTROOTS_SHELL_SCRIPT = 'onlineca-get-trustroots.sh'
GET_CERT_SHELL_SCRIPT_PATH = os.path.join(CLIENT_SHELL_SCRIPTS_DIR,
                                       GET_CERT_SHELL_SCRIPT)
GET_TRUSTROOTS_SHELL_SCRIPT_PATH = os.path.join(CLIENT_SHELL_SCRIPTS_DIR,
                                                GET_TRUSTROOTS_SHELL_SCRIPT)