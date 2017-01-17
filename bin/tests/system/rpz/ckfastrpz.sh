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


cat <<EOF
# common fastrpz configuration setttings
	fastrpz-options "dnsrpzd-conf ../dnsrpzd.conf
			dnsrpzd-sock ../dnsrpzd.sock
			dnsrpzd-rpzf ../dnsrpzd.rpzf
			dnsrpzd-args '-dddd -L stdout'";
EOF

if test -e fastrpz-off; then
    echo "## fastrpz disabled by the existence of fastrpz-off"
    exit 1
fi

if test ! -x $FASTRPZ_CMD; then
    echo "## make $FASTRPZ_CMD to test fastrpz"
    exit 1
fi

if $FASTRPZ_CMD -a 2>&1; then
    echo
else
    echo "## no fastrpz; install fastrpz to test with it"
    exit 1
fi

# Try to fetch the license
if [ ! -f fastrpz.license ]; then
    echo "## fastrpz disabled; license file missing"
    exit 1
fi

. fastrpz.license
if `$DIG -t axfr -y$KEY $NAME @$LSERVER | grep "^$NAME.*TXT" >/dev/null`; then
    echo "## testing with fastrpz"
    echo "	fastrpz-enable yes;"
    exit 0
fi

echo "## fastrpz disabled; no license for $NAME"
exit 1
