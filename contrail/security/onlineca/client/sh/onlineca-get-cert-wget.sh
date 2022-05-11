#!/bin/bash
#
# Client script for web service interface to SLCS based on openssl and
# curl
#
# @author P J Kershaw 25/05/2010
#
# @copyright: (C) 2010 STFC
#
# @license: BSD - See top-level LICENCE file for licence details
#
# $Id$
cmdname=$(basename $0)
cmdline_opt=`getopt hU:l:So:c: $*`

usage="Usage: $cmdname [-U Short-Lived Credential Service URI][-l username] ...\n
\n
   Options\n
       -h\t\t\tDisplays usage\n
       -U <uri>\t\tShort-Lived Credential service URI\n
       -l <username>\t\tUsername for the delegated proxy (defaults to \$LOGNAME)\n
       -S\t\t\tpass password from stdin rather prompt from tty\n
       -o <filepath>\t\tOutput location of end entity certificate or delegated proxy (default to stdout)\n
       -c <directory path>\tDirectory containing the trusted CA (Certificate Authority) certificates.  These are used to\n
       \t\t\tverify the identity of the Short-Lived Credential Service.  Defaults to\n
       \t\t\t${HOME}/.globus/certificates or\n
       \t\t\t/etc/grid-security/certificates if running as root.\n
"


if [ $? != 0 ] ; then
    echo -e $usage >&2 ;
    exit 1 ;
fi

set -- $cmdline_opt

while true ; do
    case "$1" in
        -h) echo -e $usage ; exit 0 ;;
        -U) uri=$2 ; shift 2 ;;
        -l) username=$2 ; shift 2 ;;
        -S) stdin_pass=True ; shift 1 ;;
        -o) outfilepath=$2 ; shift 2 ;;
        -c) cadir=$2 ; shift 2 ;;
        --) shift ; break ;;
        *) echo "Error parsing command line" ; exit 1 ;;
    esac
done

if [ -z $uri ]; then
    echo -e Give the URI for the Short-Lived Credential service logon request;
    echo -e $usage >&2 ;
    exit 1;
fi

# Default to LOGNAME if not set on command line
if [ -z $username ]; then
    username=${LOGNAME}
fi

# Read password
if [ $stdin_pass ]; then
    read password;
else
    stty -echo
    read -r -p "Enter Short-Lived Credential phrase: " password; echo
    stty echo
fi

# Set-up trust root
if [ -z $cadir ]; then
    if [ ${X509_CERT_DIR} ]; then
        cadir=${X509_CERT_DIR}
    elif [ "$username" = "root" ]; then
        cadir=/etc/grid-security/certificates
    else
        cadir=${HOME}/.globus/certificates
    fi
fi

# Set output file path
if [ -z $outfilepath ]; then
    if [ ${X509_USER_PROXY} ]; then
        outfilepath=${X509_USER_PROXY}
    else
        # Default to stdout
        outfilepath=/dev/stdout
    fi
fi

# Make a temporary file location for the certificate request and key
keyfilepath="/tmp/$UID-$RANDOM.key"
certreqfilepath="/tmp/$UID-$RANDOM.csr"

# Generate key pair and request.  The key file is written to the 'key' var
openssl req -new -newkey rsa:2048 -nodes -keyout $keyfilepath -subj //\CN=dummy -out $certreqfilepath 2> /dev/null
key=$(cat $keyfilepath)

# URL Encode certificate request - allow for '+' symbol in the base64 charset -
# needs to be hex equivalent

# Post request to Short-Lived Credential service passing username/password for HTTP Basic
# auth based authentication.
encoded_certreq=$(cat $certreqfilepath|sed s/+/%2B/g)

# Clean up certificate request and key temporary files
rm -f $keyfilepath
rm -f $certreqfilepath

response=$(wget --secure-protocol TLSv1 --ca-directory=$cadir \
--http-user=$username --http-password=$password \
--post-data "certificate_request=$encoded_certreq" \
-t 1 $uri -O - 2>&1)

# Pull out the response code from the output
wget_statcode_line="awaiting response..."
responsecode=$(echo "$response"|grep "$wget_statcode_line"|awk '{print $6}'|tail -1)
if [ "$responsecode" != "200" ]; then
    echo "Get certificate call failed: $response" >&2
    exit 1
fi

# Cut-out extraneous wget output to get certificate chain only
certchain=$(echo "$response"|sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p')

# Simple sanity check on extracted cert
if [[ $certchain != -----BEGIN\ CERTIFICATE-----* ]]; then
    echo "Expecting certificate in response; got:" >&2
    echo "$certchain" >&2
    exit 1
fi

# Separate out End Entity Certificate from any other certificates returned in 
# the trust chain. This is needed so that there is ordering consistent with
# the behaviour of MyProxyCA

# Escape line endings for private key so that it can work with awk
esc_key=$(echo "${key}" | sed '$!s@$@\\@g')

# Similarly, escape line endings for certificate chain
esc_certchain=$(echo "$certchain"| sed '$!s@$@\\@g')

# Inject private key content into response immediately after the first 
# certificate (i.e. the End Entity Certificate) in the certificate chain
output=$(awk -v certchain="${esc_certchain}" -v key="${esc_key}" 'BEGIN {\
    len = split(certchain, arr, "-----END CERTIFICATE-----"); \
    for (i=1; i < len; i++) {\
        printf "%s-----END CERTIFICATE-----", arr[i]; \
        if (i == 1) {\
            printf "\n%s", key \
        } \
    }; \
    print \
}')

# Output certificates with private key ensuring all backslashes have been
# converted back to newline characters
echo "$output"|tr -s '\\' '\n' > $outfilepath
