# Introduction

dnssec-keymgr is a high level Python wrapper to facilitate the key rollover 
for zones handled by BIND. It uses all the BIND commands for DNSSEC operations.

## How to use

dnssec-keymgr will take care of executing the needed operations to prepare a 
zone to be signed, and to move keys from one state to the next assuming the 
time conditions are met. 

It will use the contents of the keys directory to determine the timing for a 
key, find out the metadata, and determine if a key needs to be created.

### Initial setup

If you are working with a new zone, you can just simply can

```
dnssec-keymgr example.com
```

To initialize the state of a zone. It will use the default policy to 
determine key length, key algorithm and key lifetime including rollover 
period, pre and post publish period and coverage.

Finally, you can execute

```
dnssec-coverage
```

to understand if the current state of the keys provides you enough coverage 
based on the existing policy

### Full example

If you want to start managing your DNSSEC zones using `dnssec-keymgr` you can
 follow these steps.
 
1. Setup your zone in BIND. The following is just an example, you can find a 
more complete guide at [BIND DNSSEC Guide](http://users.isc.org/~jreed/dnssec-guide/dnssec-guide.html)

**named.conf**

```
zone test.nz IN {
    type master;
    file "/var/cache/bind/zones/test.nz.zone";
    key-directory "/var/cache/bind/keys";
    inline-signing yes;
    auto-dnssec maintain;
};
```

2. Generate some keys with `dnssec-keymgr`. The location of the key directory
 has to match to what was provided in the zone definition above.

```
dnssec-keymgr -K /var/cache/bind/keys/ test.nz
```

By default `dnssec-keymgr` will report what's doing

```
dnssec-keygen -q  -K /var/cache/bind/keys/ -L 3600 -a RSASHA256 -b 1024   test.nz
test.nz/RSASHA256/15246
dnssec-keygen -q -fk -K /var/cache/bind/keys/ -L 3600 -a RSASHA256 -b 2048   test.nz
test.nz/RSASHA256/15544
dnssec-settime -K /var/cache/bind/keys/ -L 3600 -I 20161229145822 -D 20170128145822 Ktest.nz.+008+15246
dnssec-keygen -q -K /var/cache/bind/keys/ -S Ktest.nz.+008+15246
dnssec-settime -K /var/cache/bind/keys/ -L 3600 -I none -D none Ktest.nz.+008+47058
```

3. Start BIND to do the signing

As this is a new zone, reload BIND to read the zone, read the keys and do the
 signing

```
rndc reload
```

Logs show

```
named[5838]: zone test.nz/IN (unsigned): loaded serial 2017040200
named[5838]: zone test.nz/IN (signed): loaded serial 2017040200
named[5838]: zone test.nz/IN (signed): receive_secure_serial: unchanged
named[5838]: zone test.nz/IN (signed): sending notifies (serial 2017040200)
named[5838]: zone test.nz/IN (signed): reconfiguring zone keys
named[5838]: zone test.nz/IN (signed): next key event: 04-Apr-2016 04:01:14.014
```

And `dnssec-coverage` tells us the state of the keys for the zone

```
dnssec-coverage -K /var/cache/bind/keys/ test.nz
WARNING: Maximum TTL value was not specified.  Using 1 week
	 (604800 seconds); re-run with the -m option to get more
	 accurate results.
PHASE 1--Loading keys to check for internal timing problems

PHASE 2--Scanning future key events for coverage failures
Checking scheduled KSK events for zone test.nz, algorithm RSASHA256...
  Sun Apr 03 14:58:22 UTC 2016:
    Publish: test.nz/RSASHA256/15544 (KSK)
    Activate: test.nz/RSASHA256/15544 (KSK)

No errors found

Checking scheduled ZSK events for zone test.nz, algorithm RSASHA256...
  Sun Apr 03 14:58:22 UTC 2016:
    Publish: test.nz/RSASHA256/15246 (ZSK)
    Activate: test.nz/RSASHA256/15246 (ZSK)
  Tue Nov 29 14:58:22 UTC 2016:
    Publish: test.nz/RSASHA256/47058 (ZSK)
  Thu Dec 29 14:58:22 UTC 2016:
    Activate: test.nz/RSASHA256/47058 (ZSK)
    Inactive: test.nz/RSASHA256/15246 (ZSK)
  Sat Jan 28 14:58:22 UTC 2017:
    Delete: test.nz/RSASHA256/15246 (ZSK)

No errors found
```
