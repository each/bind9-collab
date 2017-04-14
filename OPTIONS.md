Setting the `STD_CDEFINES` environment variable before running `configure`
can be used to enable certain compile-time options that are not explicitly
defined in `configure`.

Some of these settings are:

|Setting                            |Description |
|-----------------------------------|----------------------------------------|
|`-DISC_MEM_FILL=0`|Don't ovewrite memory when allocating or freeing it; this improves performance but makes debugging more difficult.|
|`-DISC_MEM_TRACKLINES=0`|Don't track memory allocations by file and line number; this improves performance but makes debugging more difficult.|
|<nobr>`-DISC_FACILITY=LOG_LOCAL0`</nobr>|Change the default syslog facility for `named`|
|`-DNS_CLIENT_DROPPORT=0`|Disable dropping queries from particular well-known ports:|
|`-DCHECK_SIBLING=0`|Don't check sibling glue in `named-checkzone`|
|`-DCHECK_LOCAL=0`|Don't check out-of-zone addresses in `named-checkzone`|
|`-DNS_RUN_PID_DIR=0`|Create default PID files in `${localstatedir}/run` rather than `${localstatedir}/run/{named,lwresd}/`|
|`-DDIG_SIGCHASE=1`|Enable DNSSEC signature chasing support in `dig`.  (Note: This feature is deprecated. Use `delv` instead.)|

