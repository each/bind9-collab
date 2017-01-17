#ifndef DNS_FASTRPZ_H
#define DNS_FASTRPZ_H

#include <isc/lang.h>
#include <dns/types.h>

#include <config.h>

#ifdef USE_FASTRPZ

#include <dns/librpz.h>

/*
 * Error message if dlopen(librpz) failed.
 */
extern librpz_emsg_t librpz_lib_open_emsg;


/*
 * These shim BIND9 database, node, and rdataset are handles on RRs from librpz.
 *
 * All of these structures are used by a single thread and so need no locks.
 *
 * fastdb_t holds the state for a set of RPZ queries.
 *
 * fastnode_t is a link to the fastdb_t for the set of  RPZ queries
 * and a flag saying whether it is pretending to be a node with RRs for
 * the qname or the node with the SOA for the zone containing the rewritten
 * RRs or justifying NXDOMAIN.
 */
typedef struct {
	uint8_t			unused;
} fastnode_t;
typedef struct fastdb {
	dns_db_t		common;
	int			ref_cnt;
	librpz_result_id_t	hit_id;
	librpz_result_t		result;
	librpz_rsp_t*		rsp;
	librpz_domain_buf_t	origin_buf;
	const dns_name_t	*qname;
	fastnode_t		origin_node;
	fastnode_t		data_node;
} fastdb_t;


/*
 * Convert a fastrpz policy to a classic BIND9 RPZ policy.
 */
dns_rpz_policy_t dns_fastrpz_2policy(librpz_policy_t fast_policy);

/*
 * Convert a fastrpz trigger to a classic BIND9 RPZ rewrite or trigger type.
 */
dns_rpz_type_t dns_fastrpz_trig2type(librpz_trig_t trig);

/*
 * Convert a classic BIND9 RPZ rewrite or trigger type to a librpz trigger type.
 */
librpz_trig_t dns_fastrpz_type2trig(dns_rpz_type_t type);

/*
 * Start Fastrpz for the entire server.
 */
isc_result_t dns_fastrpz_server_create(void);

/*
 * Stop Fastrpz for the entire server.
 */
void dns_fastrpz_server_destroy(void);

/*
 * Ready fastrpz for a view.
 */
isc_result_t dns_fastrpz_view_init(dns_rpz_zones_t *new, char *fast_cstr);

/*
 * Connect to and start the fastrpz daemon, dnsrpzd.
 */
isc_result_t dns_fastrpz_connect(dns_rpz_zones_t *rpzs);

/*
 * Get ready to try fastrpz rewriting.
 */
isc_result_t dns_fastrpz_rewrite_init(librpz_emsg_t *emsg, dns_rpz_st_t *st,
				      dns_rpz_zones_t *rpzs,
				      const dns_name_t *qname, isc_mem_t *mctx,
				      isc_boolean_t have_rd);

#endif /* USE_FASTRPZ */

ISC_LANG_ENDDECLS

#endif /* DNS_FASTRPZ_H */
