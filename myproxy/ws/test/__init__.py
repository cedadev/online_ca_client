"""MyProxy Web Service Utilities unit test package
"""
__author__ = "P J Kershaw"
__date__ = "25/05/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import os

test_dir = os.path.dirname(__file__)
myproxy_ws_pkg_dir = os.path.dirname(test_dir)
test_ca_dir = os.path.join(test_dir, 'ca')
client_shell_scripts_dir = os.path.join(myproxy_ws_pkg_dir, 'client')
logon_shell_script = 'myproxy-ws-logon.sh'
get_trustroots_shell_script = 'myproxy-ws-get-trustroots.sh'
logon_shell_script_path = os.path.join(client_shell_scripts_dir,
                                       logon_shell_script)
get_trustroots_shell_script_path = os.path.join(client_shell_scripts_dir,
                                                get_trustroots_shell_script)

