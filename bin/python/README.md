# Introduction

dnssec-keymgr is a high level Python wrapper to facilitate the key rollover 
for zones handled by BIND. It uses all the BIND commands for DNSSEC operations.

## How to use

dnssec-keymgr will take care of executing the needed operations to move a key
 from one state to other, assuming the time dependencies are meet. So it 
 should be safe to run it as many times as needed from a crontab.

### Generate keys

Create some keys for a zone you want to sign using

```
dnssec-keygen example.com
```

By default the key will be XXXX

Then you can run

```
dnssec-keymgr
```

and it will detect the presence of the key files as a hint of the zone that 
need management

Finally, you can execute

```
dnssec-coverage
```

to understand if the current state of the keys provides you enough coverage 
based on the existing policy

## Caveats

You will need to generate DNSSEC keys first before using dnssec-keymgr. We 
will work to have that fix at some point
