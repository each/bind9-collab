ISC
Internet Systems Consortium, Inc.
named.conf
5
BIND9
named.conf
configuration file for
named
2004
2005
2006
2007
2008
2009
2010
2011
2012
2013
2014
2015
2016
2017
Internet Systems Consortium, Inc. ("ISC")
named.conf
DESCRIPTION
===========

`named.conf` is the configuration file for `named`. Statements are enclosed in braces and terminated with a semi-colon. Clauses in the statements are also semi-colon terminated. The usual comment styles are supported:

C style: /\* \*/

C++ style: // to end of line

Unix style: \# to end of line

ACL
===

    acl string { address_match_element; ... };

KEY
===

    key domain_name {
        algorithm string;
        secret string;
    };

MASTERS
=======

    masters string  port integer  {
        ( masters | ipv4_address port integer |
        ipv6_address port integer )  key string ; ...
    };

SERVER
======

    server ( ipv4_address/prefixlen | ipv6_address/prefixlen ) {
        bogus boolean;
        edns boolean;
        edns-udp-size integer;
        max-udp-size integer;
        padding integer;
        tcp-only boolean;
        tcp-keepalive boolean;
        provide-ixfr boolean;
        request-ixfr boolean;
        keys server_key;
        transfers integer;
        transfer-format ( many-answers | one-answer );
        transfer-source ( ipv4_address | * )
             port ( integer | * ) ;
        transfer-source-v6 ( ipv6_address | * )
             port ( integer | * ) ;

        support-ixfr boolean; // obsolete
    };

TRUSTED-KEYS
============

    trusted-keys {
        domain_name flags protocol algorithm key; ...
    };

MANAGED-KEYS
============

    managed-keys {
        domain_name initial-key flags protocol algorithm key; ...
    };

CONTROLS
========

    controls {
        inet ( ipv4_address | ipv6_address | * )
             port ( integer | * ) 
            allow { address_match_element; ... }
             keys { string; ... } ;
        unix unsupported; // not implemented
    };

LOGGING
=======

    logging {
        channel string {
            file log_file;
            syslog optional_facility;
            null;
            stderr;
            severity log_severity;
            print-time boolean;
            print-severity boolean;
            print-category boolean;
        };
        category string { string; ... };
    };

LWRES
=====

    lwres {
        listen-on  port integer  {
            ( ipv4_address | ipv6_address )  port integer ; ...
        };
        view string optional_class;
        search { string; ... };
        ndots integer;
        lwres-tasks integer;
        lwres-clients integer;
    };

OPTIONS
=======

    options {
        avoid-v4-udp-ports { port; ... };
        avoid-v6-udp-ports { port; ... };
        blackhole { address_match_element; ... };
        coresize size;
        datasize size;
        directory quoted_string;
        dnstap { message_type; ... };
        dnstap-output ( file | unix ) path_name;
        dnstap-identity ( string | hostname | none );
        dnstap-version ( string | none );
        dump-file quoted_string;
        files size;
        fstrm-set-buffer-hint number;
        fstrm-set-flush-timeout number;
        fstrm-set-input-queue-size number;
        fstrm-set-output-notify-threshold number;
        fstrm-set-output-queue-model ( mpsc | spsc ) ;
        fstrm-set-output-queue-size number;
        fstrm-set-reopen-interval number;
        heartbeat-interval integer;
        host-statistics boolean; // not implemented
        host-statistics-max number; // not implemented
        hostname ( quoted_string | none );
        interface-interval integer;
        keep-response-order { address_match_element; ... };
        listen-on  port integer  { address_match_element; ... };
        listen-on-v6  port integer  { address_match_element; ... };
        match-mapped-addresses boolean;
        memstatistics-file quoted_string;
        pid-file ( quoted_string | none );
        port integer;
        querylog boolean;
        recursing-file quoted_string;
        reserved-sockets integer;
        random-device quoted_string;
        recursive-clients integer;
        serial-query-rate integer;
        server-id ( quoted_string | hostname | none );
        stacksize size;
        statistics-file quoted_string;
        statistics-interval integer; // not yet implemented
        tcp-clients integer;
        tcp-listen-queue integer;
        tkey-dhkey quoted_string integer;
        tkey-gssapi-credential quoted_string;
        tkey-gssapi-keytab quoted_string;
        tkey-domain quoted_string;
        transfer-message-size integer;
        transfers-per-ns integer;
        transfers-in integer;
        transfers-out integer;
        version ( quoted_string | none );
        allow-recursion { address_match_element; ... };
        allow-recursion-on { address_match_element; ... };
        sortlist { address_match_element; ... };
        topology { address_match_element; ... }; // not implemented
        auth-nxdomain boolean; // default changed
        minimal-any boolean;
        minimal-responses ( boolean | no-auth | no-auth-recursive );
        recursion boolean;
        rrset-order {
             class string   type string 
             name quoted_string  string string; ...
        };
        provide-ixfr boolean;
        request-ixfr boolean;
        rfc2308-type1 boolean; // not yet implemented
        additional-from-auth boolean;
        additional-from-cache boolean;
        query-source ( ( ipv4_address | * ) |  address ( ipv4_address | * )  )  port ( integer | * ) ;
        query-source-v6 ( ( ipv6_address | * ) |  address ( ipv6_address | * )  )  port ( integer | * ) ;
        use-queryport-pool boolean;
        queryport-pool-ports integer;
        queryport-pool-updateinterval integer;
        cleaning-interval integer;
        resolver-query-timeout integer;
        min-roots integer; // not implemented
        lame-ttl integer;
        max-ncache-ttl integer;
        max-cache-ttl integer;
        transfer-format ( many-answers | one-answer );
        max-cache-size size;
        max-acache-size size;
        clients-per-query number;
        max-clients-per-query number;
        check-names ( master | slave | response )
            ( fail | warn | ignore );
        check-mx ( fail | warn | ignore );
        check-integrity boolean;
        check-mx-cname ( fail | warn | ignore );
        check-srv-cname ( fail | warn | ignore );
        cache-file quoted_string; // test option
        catalog-zones {
            zone quoted_string
             default-masters
            port ip_port
            dscp ip_dscp
            { ( masters_list | ip_addr port ip_port key key ) ; ... }
            in-memory yes_or_no
            min-update-interval interval
            ; ... };
        ;
        suppress-initial-notify boolean; // not yet implemented
        preferred-glue string;
        dual-stack-servers  port integer  {
            ( quoted_string port integer |
            ipv4_address port integer |
            ipv6_address port integer ); ...
        };
        edns-udp-size integer;
        max-udp-size integer;
        root-delegation-only  exclude { quoted_string; ... } ;
        disable-algorithms string { string; ... };
        disable-ds-digests string { string; ... };
        dnssec-enable boolean;
        dnssec-validation boolean;
        dnssec-lookaside ( auto | no | domain trust-anchor domain );
        dnssec-must-be-secure string boolean;
        dnssec-accept-expired boolean;

        dns64-server string;
        dns64-contact string;
        dns64 prefix {
            clients { acl; };
            exclude { acl; };
            mapped { acl; };
            break-dnssec boolean;
            recursive-only boolean;
            suffix ipv6_address;
        };

        empty-server string;
        empty-contact string;
        empty-zones-enable boolean;
        disable-empty-zone string;

        dialup dialuptype;
        ixfr-from-differences ixfrdiff;

        allow-query { address_match_element; ... };
        allow-query-on { address_match_element; ... };
        allow-query-cache { address_match_element; ... };
        allow-query-cache-on { address_match_element; ... };
        allow-transfer { address_match_element; ... };
        allow-update { address_match_element; ... };
        allow-update-forwarding { address_match_element; ... };
        update-check-ksk boolean;
        dnssec-dnskey-kskonly boolean;

        masterfile-format ( text | raw | map );
        notify notifytype;
        notify-source ( ipv4_address | * )  port ( integer | * ) ;
        notify-source-v6 ( ipv6_address | * )  port ( integer | * ) ;
        notify-delay seconds;
        notify-to-soa boolean;
        also-notify  port integer  { ( ipv4_address | ipv6_address )
             port integer ; ...
             key keyname  ... };
        allow-notify { address_match_element; ... };

        forward ( first | only );
        forwarders  port integer  {
            ( ipv4_address | ipv6_address )  port integer ; ...
        };

        max-journal-size size_no_default;
        max-records integer;
        max-transfer-time-in integer;
        max-transfer-time-out integer;
        max-transfer-idle-in integer;
        max-transfer-idle-out integer;
        max-retry-time integer;
        min-retry-time integer;
        max-refresh-time integer;
        min-refresh-time integer;
        multi-master boolean;

        sig-validity-interval integer;
        sig-re-signing-interval integer;
        sig-signing-nodes integer;
        sig-signing-signatures integer;
        sig-signing-type integer;

        transfer-source ( ipv4_address | * )
             port ( integer | * ) ;
        transfer-source-v6 ( ipv6_address | * )
             port ( integer | * ) ;

        alt-transfer-source ( ipv4_address | * )
             port ( integer | * ) ;
        alt-transfer-source-v6 ( ipv6_address | * )
             port ( integer | * ) ;
        use-alt-transfer-source boolean;

        zone-statistics boolean;
        key-directory quoted_string;
        managed-keys-directory quoted_string;
        auto-dnssec allow|maintain|off;
        try-tcp-refresh boolean;
        zero-no-soa-ttl boolean;
        zero-no-soa-ttl-cache boolean;
        dnssec-secure-to-insecure boolean;
        automatic-interface-scan boolean;

        cookie-algorithm ( aes | sha1 | sha256 );
        cookie-secret string;
        require-server-cookie boolean;
        send-cookie boolean;
        nocookie-udp-size integer;

        response-padding {
            address_match_list
        } block-size integer;

        deny-answer-addresses {
            address_match_list
        }  except-from { namelist } ;
        deny-answer-aliases {
            namelist
        }  except-from { namelist } ;

        nsec3-test-zone boolean;  // testing only

        allow-v6-synthesis { address_match_element; ... }; // obsolete
        deallocate-on-exit boolean; // obsolete
        fake-iquery boolean; // obsolete
        fetch-glue boolean; // obsolete
        has-old-clients boolean; // obsolete
        maintain-ixfr-base boolean; // obsolete
        max-ixfr-log-size size; // obsolete
        multiple-cnames boolean; // obsolete
        named-xfer quoted_string; // obsolete
        serial-queries integer; // obsolete
        treat-cr-as-space boolean; // obsolete
        use-id-pool boolean; // obsolete
        use-ixfr boolean; // obsolete
    };

VIEW
====

    view string optional_class {
        match-clients { address_match_element; ... };
        match-destinations { address_match_element; ... };
        match-recursive-only boolean;

        key string {
            algorithm string;
            secret string;
        };

        zone string optional_class {
            ...
        };

        server ( ipv4_address/prefixlen | ipv6_address/prefixlen ) {
            ...
        };

        trusted-keys {
            string integer integer integer quoted_string;
            ...
        };

        managed-keys {
            domain_name initial-key flags protocol algorithm key;
            ...
        };

        allow-recursion { address_match_element; ... };
        allow-recursion-on { address_match_element; ... };
        sortlist { address_match_element; ... };
        topology { address_match_element; ... }; // not implemented
        auth-nxdomain boolean; // default changed
        minimal-any boolean;
        minimal-responses boolean;
        recursion boolean;
        rrset-order {
             class string   type string 
             name quoted_string  string string; ...
        };
        provide-ixfr boolean;
        request-ixfr boolean;
        rfc2308-type1 boolean; // not yet implemented
        additional-from-auth boolean;
        additional-from-cache boolean;
        query-source ( ( ipv4_address | * ) |  address ( ipv4_address | * )  )  port ( integer | * ) ;
        query-source-v6 ( ( ipv6_address | * ) |  address ( ipv6_address | * )  )  port ( integer | * ) ;
        use-queryport-pool boolean;
        queryport-pool-ports integer;
        queryport-pool-updateinterval integer;
        cleaning-interval integer;
        resolver-query-timeout integer;
        min-roots integer; // not implemented
        lame-ttl integer;
        max-ncache-ttl integer;
        max-cache-ttl integer;
        transfer-format ( many-answers | one-answer );
        max-cache-size size;
        max-acache-size size;
        clients-per-query number;
        max-clients-per-query number;
        check-names ( master | slave | response )
            ( fail | warn | ignore );
        check-mx ( fail | warn | ignore );
        check-integrity boolean;
        check-mx-cname ( fail | warn | ignore );
        check-srv-cname ( fail | warn | ignore );
        cache-file quoted_string; // test option
        suppress-initial-notify boolean; // not yet implemented
        preferred-glue string;
        dual-stack-servers  port integer  {
            ( quoted_string port integer |
            ipv4_address port integer |
            ipv6_address port integer ); ...
        };
        edns-udp-size integer;
        max-udp-size integer;
        root-delegation-only  exclude { quoted_string; ... } ;
        disable-algorithms string { string; ... };
        disable-ds-digests string { string; ... };
        dnssec-enable boolean;
        dnssec-validation boolean;
        dnssec-lookaside ( auto | no | domain trust-anchor domain );
        dnssec-must-be-secure string boolean;
        dnssec-accept-expired boolean;

        dns64-server string;
        dns64-contact string;
        dns64 prefix {
            clients { acl; };
            exclude { acl; };
            mapped { acl; };
            break-dnssec boolean;
            recursive-only boolean;
            suffix ipv6_address;
        };

        empty-server string;
        empty-contact string;
        empty-zones-enable boolean;
        disable-empty-zone string;

        dialup dialuptype;
        ixfr-from-differences ixfrdiff;

        allow-query { address_match_element; ... };
        allow-query-on { address_match_element; ... };
        allow-query-cache { address_match_element; ... };
        allow-query-cache-on { address_match_element; ... };
        allow-transfer { address_match_element; ... };
        allow-update { address_match_element; ... };
        allow-update-forwarding { address_match_element; ... };
        update-check-ksk boolean;
        dnssec-dnskey-kskonly boolean;

        masterfile-format ( text | raw | map );
        notify notifytype;
        notify-source ( ipv4_address | * )  port ( integer | * ) ;
        notify-source-v6 ( ipv6_address | * )  port ( integer | * ) ;
        notify-delay seconds;
        notify-to-soa boolean;
        also-notify  port integer  { ( ipv4_address | ipv6_address )
             port integer ; ...
             key keyname  ... };
        allow-notify { address_match_element; ... };

        forward ( first | only );
        forwarders  port integer  {
            ( ipv4_address | ipv6_address )  port integer ; ...
        };

        max-journal-size size_no_default;
        max-records integer;
        max-transfer-time-in integer;
        max-transfer-time-out integer;
        max-transfer-idle-in integer;
        max-transfer-idle-out integer;
        max-retry-time integer;
        min-retry-time integer;
        max-refresh-time integer;
        min-refresh-time integer;
        multi-master boolean;
        sig-validity-interval integer;

        transfer-source ( ipv4_address | * )
             port ( integer | * ) ;
        transfer-source-v6 ( ipv6_address | * )
             port ( integer | * ) ;

        alt-transfer-source ( ipv4_address | * )
             port ( integer | * ) ;
        alt-transfer-source-v6 ( ipv6_address | * )
             port ( integer | * ) ;
        use-alt-transfer-source boolean;

        zone-statistics boolean;
        try-tcp-refresh boolean;
        key-directory quoted_string;
        zero-no-soa-ttl boolean;
        zero-no-soa-ttl-cache boolean;
        dnssec-secure-to-insecure boolean;

        require-server-cookie boolean;
        send-cookie boolean;
        nocookie-udp-size integer;

        allow-v6-synthesis { address_match_element; ... }; // obsolete
        fetch-glue boolean; // obsolete
        maintain-ixfr-base boolean; // obsolete
        max-ixfr-log-size size; // obsolete
    };

ZONE
====

    zone string optional_class {
        type ( master | slave | stub | hint | redirect |
            forward | delegation-only );
        file quoted_string;

        masters  port integer  {
            ( masters |
            ipv4_address port integer |
            ipv6_address  port integer  )  key string ; ...
        };

        database string;
        delegation-only boolean;
        check-names ( fail | warn | ignore );
        check-mx ( fail | warn | ignore );
        check-integrity boolean;
        check-mx-cname ( fail | warn | ignore );
        check-srv-cname ( fail | warn | ignore );
        dialup dialuptype;
        ixfr-from-differences boolean;
        journal quoted_string;
        zero-no-soa-ttl boolean;
        dnssec-secure-to-insecure boolean;

        allow-query { address_match_element; ... };
        allow-query-on { address_match_element; ... };
        allow-transfer { address_match_element; ... };
        allow-update { address_match_element; ... };
        allow-update-forwarding { address_match_element; ... };
        update-policy local |  {
            ( grant | deny ) string
            ( name | subdomain | wildcard | self | selfsub | selfwild |
              krb5-self | ms-self | krb5-subdomain | ms-subdomain |
              tcp-self | zonesub | 6to4-self ) string
            rrtypelist;
            ...
        };
        update-check-ksk boolean;
        dnssec-dnskey-kskonly boolean;

        masterfile-format ( text | raw | map );
        notify notifytype;
        notify-source ( ipv4_address | * )  port ( integer | * ) ;
        notify-source-v6 ( ipv6_address | * )  port ( integer | * ) ;
        notify-delay seconds;
        notify-to-soa boolean;
        also-notify  port integer  { ( ipv4_address | ipv6_address )
             port integer ; ...
             key keyname  ... };
        allow-notify { address_match_element; ... };

        forward ( first | only );
        forwarders  port integer  {
            ( ipv4_address | ipv6_address )  port integer ; ...
        };

        max-journal-size size_no_default;
        max-records integer;
        max-transfer-time-in integer;
        max-transfer-time-out integer;
        max-transfer-idle-in integer;
        max-transfer-idle-out integer;
        max-retry-time integer;
        min-retry-time integer;
        max-refresh-time integer;
        min-refresh-time integer;
        multi-master boolean;
        request-ixfr boolean;
        sig-validity-interval integer;

        transfer-source ( ipv4_address | * )
             port ( integer | * ) ;
        transfer-source-v6 ( ipv6_address | * )
             port ( integer | * ) ;

        alt-transfer-source ( ipv4_address | * )
             port ( integer | * ) ;
        alt-transfer-source-v6 ( ipv6_address | * )
             port ( integer | * ) ;
        use-alt-transfer-source boolean;

        zone-statistics boolean;
        try-tcp-refresh boolean;
        key-directory quoted_string;

        nsec3-test-zone boolean;  // testing only

        ixfr-base quoted_string; // obsolete
        ixfr-tmp-file quoted_string; // obsolete
        maintain-ixfr-base boolean; // obsolete
        max-ixfr-log-size size; // obsolete
        pubkey integer integer integer quoted_string; // obsolete
    };

FILES
=====

`/etc/named.conf`

SEE ALSO
========

named8, named-checkconf8, rndc8, BIND 9 Administrator Reference Manual.
