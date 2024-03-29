"""
Command-line interface to Online Certificate Authority.

Sub commands
------------

``onlineca-client get-cert`` retrieve a new certificate based on
user credentials
"""

__author__ = "Philip Kershaw"
__date__ = "23/01/2017"
__copyright__ = "(C) 2017 Science and Technology Facilities Council"
__license__ = __license__ = """BSD - See LICENSE file in top-level directory"""
__revision__ = "$Id$"
import os
import sys
import logging
import getpass
import warnings
from argparse import ArgumentParser, ArgumentError

from requests.packages.urllib3.exceptions import InsecureRequestWarning

from contrail.security.onlineca.client import OnlineCaClient
from contrail.security.onlineca.client.oauth2_web_client import (
    OAuthAuthorisationCodeFlowClient,
)

log = logging.getLogger(__name__)


class OnlineCaClientCLI(object):
    """Online CA Client command line client interface"""

    GET_TRUSTROOTS_CMD = "get_trustroots"
    GET_CERT_CMD = "get_cert"
    GET_ACCESS_TOK_CMD = "get_token"

    USERNAME_ARGNAMES = ("-l", "--username")
    PASSWD_ARGNAMES = ("-P", "--stdin-password")

    DEF_CACERT_DIR = os.path.join(os.path.expanduser("~"), ".onlineca", "certificates")
    PEM_OUT_TO_STDOUT = "-"
    TOK_FILEPATH_DEF_FLAG = "-"

    def __init__(self):
        self.clnt = OnlineCaClient()

    def _get_cert(self, cmdline_args):
        """Issue certificate based on command line arguments

        :type cmdline_args: argparse.Namespace
        :param cmdline_args: command line arguments from argparse
        ArgumentParser
        """
        if cmdline_args.tok_filepath:
            if cmdline_args.username or cmdline_args.stdin_password:
                raise ArgumentError(
                    None,
                    f"Username {self.USERNAME_ARGNAMES} "
                    f"and password {self.PASSWD_ARGNAMES} "
                    "arguments are not needed when using OAuth "
                    "token option",
                )

            if cmdline_args.tok_filepath == self.TOK_FILEPATH_DEF_FLAG:
                access_tok = OnlineCaClient.read_oauth_tok()
            else:
                access_tok = OnlineCaClient.read_oauth_tok(
                    tok_filepath=cmdline_args.tok_filepath
                )

            self.clnt.get_delegated_certificate(
                access_tok,
                cmdline_args.server_url,
                pem_out_filepath=cmdline_args.pem_out_filepath,
            )
            return

        if cmdline_args.stdin_password:
            password = sys.stdin.readline().rstrip()
        else:
            password = getpass.getpass(
                "Enter password for user {} on Online "
                "CA server {}:".format(cmdline_args.username, cmdline_args.server_url)
            )

        # Set the username default here rather than via argparse so that we can
        # test for user explicitly and erroneously setting username in the above
        # when the token switch has been set
        if cmdline_args.username:
            username = cmdline_args.username
        else:
            username = os.environ.get("LOGNAME", "")

        self.clnt.get_certificate(
            username,
            password,
            cmdline_args.server_url,
            pem_out_filepath=cmdline_args.pem_out_filepath,
        )

    def _get_trustroots(self, cmdline_args):
        """Retrieve Certificate Authority certificates for bootstrapping trust
        with the Online CA service

        :type      cmdline_args: argparse.Namespace
        :param     cmdline_args: command line arguments from argparse
        ArgumentParser
        """
        self.clnt.ca_cert_dir = cmdline_args.ca_cert_dir
        self.clnt.get_trustroots(
            cmdline_args.server_url,
            write_to_ca_cert_dir=True,
            bootstrap=cmdline_args.bootstrap,
        )

    def _get_access_tok(self, cmdline_args):
        """Get OAuth 2.0 access token invoking authorisation code flow with
        a web server and browser
        """
        clnt = OAuthAuthorisationCodeFlowClient(
            settings_filepath=cmdline_args.settings_filepath,
            tok_filepath=cmdline_args.tok_filepath,
        )
        clnt.get_access_tok()

        # completed
        print(f"Access token written to '{clnt.tok_filepath}'")

    def main(self, *args):
        """Main method for parsing arguments from the command line or input
        tuple and calling appropriate command

        :type *args: tuple
        :param *args: list containing command line arguments.  If not set,
        arguments are set from sys.argv
        """

        parser = ArgumentParser(description="Online CA (Certificate Authority) Client")

        parser.add_argument(
            "-d",
            "--debug",
            action="store_true",
            dest="debug",
            default=False,
            help="Print debug information.",
        )

        sub_parsers = parser.add_subparsers(help="Set required command:")

        # Get trustroots command configuration
        get_trustroots_descr_and_help = (
            "Retrieve Certificate Authority trust "
            "roots to bootstrap trust with the "
            "Online CA service"
        )

        get_trustroots_arg_parser = sub_parsers.add_parser(
            self.__class__.GET_TRUSTROOTS_CMD,
            help=get_trustroots_descr_and_help,
            description=get_trustroots_descr_and_help,
        )

        get_trustroots_arg_parser.add_argument(
            "-s",
            "--server-url",
            dest="server_url",
            metavar="<get trust roots URL>",
            help="Server URL for Get trust " "roots request",
        )

        get_trustroots_arg_parser.add_argument(
            "-c",
            "--ca-cert-dir",
            dest="ca_cert_dir",
            metavar="<CA certificate directory>",
            default=self.__class__.DEF_CACERT_DIR,
            help="Directory to write CA certificate trustroots "
            "to.  The directory is created if it doesn't "
            "already exist",
        )

        get_trustroots_arg_parser.add_argument(
            "-b",
            "--bootstrap",
            action="store_true",
            dest="bootstrap",
            default=False,
            help="Bootstrap trust in Online " "CA server",
        )

        get_trustroots_arg_parser.set_defaults(func=self._get_trustroots)

        # Configuration for getting OAuth access token
        get_access_tok_descr_and_help = (
            "Obtain OAuth access token in order retrieve certificate by this "
            "token instead of username and password. This command involves "
            "launching an interactive web session with a browser"
        )

        get_access_tok_arg_parser = sub_parsers.add_parser(
            self.__class__.GET_ACCESS_TOK_CMD,
            help=get_access_tok_descr_and_help,
            description=get_access_tok_descr_and_help,
        )

        get_access_tok_arg_parser.add_argument(
            "-t",
            "--token",
            default=OnlineCaClient.DEF_OAUTH_TOK_FILEPATH,
            metavar="<token file path>",
            dest="tok_filepath",
            help="File location to store OAuth access token. If omitted "
            "the token will be written to the default "
            "{!r}.".format(OnlineCaClient.DEF_OAUTH_TOK_FILEPATH),
        )

        get_access_tok_arg_parser.add_argument(
            "-f",
            "--settings",
            dest="settings_filepath",
            default=OAuthAuthorisationCodeFlowClient.DEF_SETTINGS_FILEPATH,
            metavar="<settings file path>",
            help="Specify YAML format file containing required "
            "settings for interaction with OAuth 2.0 service"
            " needed to obtain an access token",
        )

        get_access_tok_arg_parser.set_defaults(func=self._get_access_tok)

        # Get certificate command configuration
        get_cert_descr_and_help = "Obtain a new certificate from an Online CA"
        get_cert_arg_parser = sub_parsers.add_parser(
            self.__class__.GET_CERT_CMD,
            help=get_cert_descr_and_help,
            description=get_cert_descr_and_help,
        )

        get_cert_arg_parser.add_argument(
            "-s",
            "--server-url",
            dest="server_url",
            required=True,
            metavar="<get certificate URL>",
            help="Server URL for Get Certificate " "request",
        )

        get_cert_arg_parser.add_argument(
            *self.USERNAME_ARGNAMES,
            dest="username",
            metavar="<username>",
            help="Set username.  Defaults to "
            '"LOGNAME" environment variable '
            "setting.",
        )

        get_cert_arg_parser.add_argument(
            *self.PASSWD_ARGNAMES,
            action="store_true",
            dest="stdin_password",
            help="Password for authentication with Online CA "
            "service.  If omitted, the program will prompt "
            "for the setting.",
        )

        get_cert_arg_parser.add_argument(
            "-t",
            "--token",
            dest="tok_filepath",
            default=OnlineCaClient.DEF_OAUTH_TOK_FILEPATH,
            metavar="<token file path>",
            help="Obtain certificate using an OAuth token "
            "contained in the specified file. If file is set "
            "to '-', then the default location "
            f"'{OnlineCaClient.DEF_OAUTH_TOK_FILEPATH}' will "
            "be used. The token file can be obtained using the '"
            f"{self.GET_ACCESS_TOK_CMD}' command. '-s', '-l' "
            "and '-P' options are not required when using this "
            "option",
        )

        get_cert_arg_parser.add_argument(
            "-o",
            "--out",
            dest="pem_out_filepath",
            metavar="<output credential file>",
            default=self.__class__.PEM_OUT_TO_STDOUT,
            help="Output path for file containing PEM-encoded "
            "private key and newly issued certificate.  "
            "Defaults to stdout",
        )

        get_cert_arg_parser.add_argument(
            "-c",
            "--ca-cert-dir",
            dest="ca_cert_dir",
            metavar="<CA certificate directory>",
            default=self.__class__.DEF_CACERT_DIR,
            help="Directory containing CA certificate trustroots " "for trusting",
        )

        get_cert_arg_parser.set_defaults(func=self._get_cert)

        # Parses from arguments input to this method if set, otherwise parses
        # from sys.argv
        if len(args) > 0:
            parsed_args = parser.parse_args(args)
        else:
            parsed_args = parser.parse_args()

        if parsed_args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        # Call appropriate command function assigned via set_defaults calls
        # above
        if hasattr(parsed_args, "func"):
            try:
                # Suppress insecure SSL connection warning for bootstrap option:
                # in this case SSL peer verification is being deliberately
                # disabled in order to initial PKI trust settings
                if hasattr(parsed_args, "bootstrap"):
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", InsecureRequestWarning)
                        parsed_args.func(parsed_args)
                else:
                    parsed_args.func(parsed_args)

            except Exception as e:
                if parsed_args.debug:
                    raise
                else:
                    parser.error(str(e))
        else:
            # func attribute is not defined if no arguments are passed
            parser.print_help()
            raise SystemExit(1)


def main():
    """Certificate Authority CLI - Wrapper for use by script entry point"""
    OnlineCaClientCLI().main()
