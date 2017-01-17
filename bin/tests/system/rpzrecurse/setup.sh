#!/bin/sh
#
# Copyright (C) 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# touch fastrpz-off to not test with fastrpz

set -e

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

$SHELL clean.sh

perl testgen.pl
cp -f ns2/named.default.conf ns2/named.conf
cp -f ns3/named1.conf ns3/named.conf

# decide whether to use fastrpz
if sh ../rpz/ckfastrpz.sh >fastrpz.conf; then
    HAVE_FASTRPZ=yes
else
    HAVE_FASTRPZ=
fi

# fastrpz configuration for named processes that do not start dnsrpzd
sed -e "s/stdout'/& dnsrpzd ''/" fastrpz.conf >fastrpz-slave.conf

DNSRPZD_LCONF=`pwd`
DNSRPZD_LCONF=`dirname $DNSRPZD_LCONF`/rpz/dnsrpzd-license.conf
cat <<EOF >dnsrpzd.conf
PID-FILE `pwd`/dnsrpzd.pid;

include "$DNSRPZD_LCONF"

zone "policy" { type master; file "`pwd`/ns3/policy.db"; };
EOF
sed -n -e 's/^ *//' -e "/zone.*.*master/s@file \"@&`pwd`/ns2/@p" ns2/*.conf \
    >>dnsrpzd.conf

# Run dnsrpzd to prime the static policy zones if we have fastrpz.
if test -n $HAVE_FASTRPZ; then
    DNSRPZD="`../rpz/fastrpz -p`"
    "$DNSRPZD" -D./dnsrpzd.rpzf -S./dnsrpzd.sock -C./dnsrpzd.conf \
		-w 0 -dddd -L stdout >./dnsrpzd.run 2>&1
    cd ..
fi
