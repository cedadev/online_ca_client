#
# Makefile to generate epydoc documentation for the MyProxy Web Service Package
#
# NERC Data Grid Project
#
# @author P J Kershaw 08/06/10
#

# @copyright: (C) 2010 STFC
#
# @license: BSD see top-level directory
#
# $Id$

# Generate HTML from embedded epydoc text in source code.
EPYDOC=epydoc
EPYDOC_INDIR=../myproxy
EPYDOC_OUTDIR=.
EPYDOC_NAME='MyProxy Web service'
EPYDOC_LOGFILE=epydoc.log
EPYDOC_OPTS=--no-frames --include-log --graph=all -v
ZIP=zip
ZIP_OUTFILE=./documentation.zip
ZIP_INFILES=./*.*

epydoc:
	${EPYDOC} ${EPYDOC_INDIR} -o ${EPYDOC_OUTDIR} --name ${EPYDOC_NAME} \
	${EPYDOC_OPTS} > ${EPYDOC_LOGFILE}
    
zip: epydoc
	${ZIP} ${ZIP_OUTFILE} ${ZIP_INFILES}	

clean:
	rm -f *.txt *.html *.gif *.css *.js *.png *.log *.zip
