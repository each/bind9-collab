ISC
Internet Systems Consortium, Inc.
lwresd
8
BIND9
lwresd
lightweight resolver daemon
2000
2001
2004
2005
2007
2008
2009
2014
2015
2016
Internet Systems Consortium, Inc. ("ISC")
lwresd
-c
config-file
-C
config-file
-d
debug-level
-f
-g
-i
pid-file
-m
flag
-n
\#cpus
-P
port
-p
port
-s
-t
directory
-u
user
-v
-4
-6
DESCRIPTION
===========

`lwresd` is the daemon providing name lookup services to clients that use the BIND 9 lightweight resolver library. It is essentially a stripped-down, caching-only name server that answers queries using the BIND 9 lightweight resolver protocol rather than the DNS protocol.

`lwresd` listens for resolver queries on a UDP port on the IPv4 loopback interface, 127.0.0.1. This means that `lwresd` can only be used by processes running on the local machine. By default, UDP port number 921 is used for lightweight resolver requests and responses.

Incoming lightweight resolver requests are decoded by the server which then resolves them using the DNS protocol. When the DNS lookup completes, `lwresd` encodes the answers in the lightweight resolver format and returns them to the client that made the request.

If `/etc/resolv.conf` contains any `nameserver` entries, `lwresd` sends recursive DNS queries to those servers. This is similar to the use of forwarders in a caching name server. If no `nameserver` entries are present, or if forwarding fails, `lwresd` resolves the queries autonomously starting at the root name servers, using a built-in list of root server hints.

OPTIONS
=======

-4  
Use IPv4 only even if the host machine is capable of IPv6. `-4` and `-6` are mutually exclusive.

-6  
Use IPv6 only even if the host machine is capable of IPv4. `-4` and `-6` are mutually exclusive.

-c config-file  
Use config-file as the configuration file instead of the default, `/etc/lwresd.conf`. `-c` can not be used with `-C`.

-C config-file  
Use config-file as the configuration file instead of the default, `/etc/resolv.conf`. `-C` can not be used with `-c`.

-d debug-level  
Set the daemon's debug level to debug-level. Debugging traces from `lwresd` become more verbose as the debug level increases.

-f  
Run the server in the foreground (i.e. do not daemonize).

-g  
Run the server in the foreground and force all logging to `stderr`.

-i pid-file  
Use pid-file as the PID file instead of the default, `/var/run/lwresd/lwresd.pid`.

-m flag  
Turn on memory usage debugging flags. Possible flags are usage, trace, record, size, and mctx. These correspond to the ISC\_MEM\_DEBUGXXXX flags described in `<isc/mem.h>`.

-n \#cpus  
Create \#cpus worker threads to take advantage of multiple CPUs. If not specified, `lwresd` will try to determine the number of CPUs present and create one thread per CPU. If it is unable to determine the number of CPUs, a single worker thread will be created.

-P port  
Listen for lightweight resolver queries on port port. If not specified, the default is port 921.

-p port  
Send DNS lookups to port port. If not specified, the default is port 53. This provides a way of testing the lightweight resolver daemon with a name server that listens for queries on a non-standard port number.

-s  
Write memory usage statistics to `stdout` on exit.

> **Note**
>
> This option is mainly of interest to BIND 9 developers and may be removed or changed in a future release.

-t directory  
Chroot to directory after processing the command line arguments, but before reading the configuration file.

> **Warning**
>
> This option should be used in conjunction with the `-u` option, as chrooting a process running as root doesn't enhance security on most systems; the way `chroot(2)` is defined allows a process with root privileges to escape a chroot jail.

-u user  
Setuid to user after completing privileged operations, such as creating sockets that listen on privileged ports.

-v  
Report the version number and exit.

FILES
=====

`/etc/resolv.conf`  
The default configuration file.

`/var/run/lwresd.pid`  
The default process-id file.

SEE ALSO
========

named8, lwres3, resolver5.
