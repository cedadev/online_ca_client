#!/bin/bash 
#
# Client script for web service interface to MyProxy get-trustroots based on 
# curl and base64 commands.  Get trust roots retrieves the CA certificate 
# issuer(s) of the MyProxy server's SSL certificate
#
# @author P J Kershaw 07/06/2010
#
# @copyright: (C) 2010 STFC
#
# @license: BSD - See top-level LICENCE file for licence details
#
# $Id$
cmdname=$(basename $0)
cmdline_opt=`getopt hU:bc: $*`

usage="Usage: $cmdname [-h][-U get trust roots URI][-b][-c CA directory]\n
\n
   Options\n
       -h\t\t\tDisplays usage and quits.\n
       -U <uri>\t\tMyProxy web service URI\n
       -b\t\t\tbootstrap trust in the MyProxy Server\n
       -c <directory path>\tDirectory to store the trusted CA (Certificate Authority) certificates.\n
       \t\t\tDefaults to ${HOME}/.globus/certificates or\n
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
        -b) bootstrap=1 ; shift 1 ;;
        -c) cadir=$2 ; shift 2 ;;
         --) shift ; break ;;
        *) echo "Error parsing command line" ; exit 1 ;;
    esac
done

if [ -z $uri ]; then
    echo -e Give the URI for the MyProxy web service get trust roots request;
    echo -e $usage >&2 ;
    exit 1;
fi

# Set-up destination trust root directory
if [ -z $cadir ]; then
    if [ ${X509_CERT_DIR} ]; then
        cadir=${X509_CERT_DIR}
    
    elif [ "$LOGNAME" = "root" ]; then
        cadir=/etc/grid-security/certificates
    else
        cadir=${HOME}/.globus/certificates
    fi
fi

# Make the directory path if it doesn't already exist
if [ ! -d $cadir ]; then
    mkdir -p $cadir
fi


# Set peer authentication based on bootstrap command line setting
if [ -z $bootstrap ]; then 
    ca_arg="--capath $cadir"
else
    echo Bootstrapping MyProxy server root of trust.
    ca_arg="--insecure"
fi

# Post request to MyProxy web service
response=$(curl $uri --sslv3 $ca_arg -w " %{http_code}" -s -S)
responsemsg=$(echo "$response"|sed '$s/ *\([^ ]* *\)$//')
responsecode=$(echo $response|awk '{print $NF}')
if [ "$responsecode" != "200" ]; then
    echo "$responsemsg" >&2
    exit 1
fi

# Process response
entries=$(echo $responsemsg|awk '{print $0}')
for i in $entries; do
    filename=${i%%=*}
    filecontent="$(echo ${i#*=}|awk '{for(i=1;i<length;i+=65) print substr($0,i,65)}'|openssl enc -d -base64)"
    echo "$filecontent" > $cadir/$filename
done

echo Trust roots have been installed in $cadir.
