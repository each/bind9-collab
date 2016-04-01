#!/bin/sh
KEYGEN=../../dnssec/dnssec-keygen
SETTIME=../../dnssec/dnssec-settime
COVERAGE=../dnssec-coverage
KEYMGR=../dnssec-keymgr

# clean up
rm -f Kexample.com*

echo "construct a key series with 6-month rollover cycle"
# KSK
$KEYGEN -q3fk example.com
# ZSK series
k1=`$KEYGEN -q3 example.com`
$SETTIME -I now+6mo -D now+8mo $k1 > /dev/null
k2=`$KEYGEN -q -S ${k1}.key`
$SETTIME -I now+1y -D now+14mo $k2 > /dev/null
k3=`$KEYGEN -q -S ${k2}.key`
$SETTIME -I now+18mo -D now+20mo $k3 > /dev/null
k4=`$KEYGEN -q -S ${k3}.key`

echo "--------------------------------------------"
echo "initial coverage:"
$COVERAGE -z example.com

echo "--------------------------------------------"
echo "applying policy for 1-year rollover cycle"
$KEYMGR -z example.com

echo "--------------------------------------------"
echo "coverage with new policy:"
$COVERAGE -z example.com

# clean up again
rm -f Kexample*

echo "--------------------------------------------"
echo "construct a key series with insufficient coverage"
$KEYGEN -q3 -I now+6mo -D now+8mo example.com

echo "--------------------------------------------"
echo "initial coverage:"
$COVERAGE -z -l1y example.com

echo "--------------------------------------------"
echo "applying policy for 1-year coverage"
$KEYMGR -z example.com

echo "--------------------------------------------"
echo "coverage with new policy:"
$COVERAGE -z example.com

# clean up again
rm -f Kexample*

