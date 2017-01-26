#! /bin/sh
#
# Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

set -e

# Say whether to test fastrpz on stdout


SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

FASTRPZ_CMD=../rpz/fastrpz

AS_NS=
MCONF=fastrpz.conf
SCONF=fastrpz-slave.conf
USAGE="$0: [-xA]  -M fastrpz.conf  -S fastrpz-slave.conf"
while getopts "xAC:S:" c; do
    case $c in
	x) set -x; DEBUG=-x;;
	A) AS_NS=yes;;
	M) MCONF="$OPTARG";;
	S) SCONF="$OPTARG";;
	*) echo "$USAGE" 1>&2; exit 1;;
    esac
done
shift `expr $OPTIND - 1 || true`
if test "$#" -ne 0; then
    echo "$USAGE" 1>&2
    exit 1
fi


CMN="	fastrpz-options \"dnsrpzd-conf ../dnsrpzd.conf
			dnsrpzd-sock ../dnsrpzd.sock
			dnsrpzd-rpzf ../dnsrpzd.rpzf
			dnsrpzd-args '-dddd -L stdout'"

MASTER="$CMN
			log-level 3"
if test -n "$AS_NS"; then
    MASTER="$MASTER
			qname-as-ns yes
			ip-as-ns yes"
fi

wfiles () {
    # write fastrpz setttings for master resolver
    cat <<EOF >$MCONF
$MASTER";
$1
EOF

    # write fastrpz setttings resolvers that should not start dnsrpzd
    cat <<EOF >$SCONF
$CMN
			dnsrpzd ''";
$1
EOF
    exit 0
}


test -e fastrpz-off && \
    wfiles "## fastrpz disabled by the existence of fastrpz-off"

test ! -x $FASTRPZ_CMD &&
    wfiles "## make $FASTRPZ_CMD to test fastrpz"

$FASTRPZ_CMD -a 2>&1 || \
    wfiles "## no fastrpz tests; install fastrpz to test with it"

# Try to fetch the license
# use alt-dnsrpzd-license.conf if it exists
LCONF=../rpz/alt-dnsrpzd-license.conf
CLCONF=dnsrpzd-license-cur.conf
test -f $LCONF || LCONF=../rpz/dnsrpzd-license.conf
cp $LCONF $CLCONF

NAME=`sed -n -e '/^zone/s/.* \([-a-z0-9]*.license.fastrpz.com\).*/\1/p' $CLCONF`
test -z "$NAME" && \
    wfiles "## no fastrpz tests; no license domain name in $CLCONF"

# This TSIG key is common and NOT a secret
KEY='hmac-sha256:farsight_fastrpz_license:f405d02b4c8af54855fcebc1'
LSERVER=license1.fastrpz.com
if `$DIG -t axfr -y$KEY $NAME @$LSERVER | grep "^$NAME.*TXT" >/dev/null`; then
    wfiles "## testing with fastrpz
	fastrpz-enable yes;"
fi

wfiles "## fastrpz tests disabled without a license for $NAME"
