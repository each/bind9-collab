/*
 * Copyright (C) 2011-2015  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*! \file */

#include <config.h>

#ifdef USE_FASTRPZ

#include <isc/mem.h>
#include <isc/string.h>

#include <dns/db.h>
#define LIBRPZ_LIB_OPEN FASTRPZ_LIB_OPEN
#include <dns/fastrpz.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/result.h>
#include <dns/rpz.h>

librpz_t *librpz;
librpz_emsg_t librpz_lib_open_emsg;
static void *librpz_handle;

#define FASTDB_MAGIC ISC_MAGIC('R', 'P', 'Z', 'F')
#define VALID_FASTDB(fastdb) ((fastdb)->common.impmagic == FASTDB_MAGIC)

#define RD_DB(r)	((r)->private1)
#define RD_CUR_RR(r)	((r)->private2)
#define RD_NEXT_RR(r)	((r)->resign)
#define RD_COUNT(r)	((r)->privateuint4)

typedef struct {
	dns_rdatasetiter_t	common;
	dns_rdatatype_t		type;
	dns_rdataclass_t	class;
	uint32_t		ttl;
	uint			count;
	librpz_idx_t		next_rr;
} fastdb_rdatasetiter_t;

static dns_dbmethods_t fastdb_db_methods;
static dns_rdatasetmethods_t fastdb_rdataset_methods;
static dns_rdatasetitermethods_t fastdb_rdatasetiter_methods;

static librpz_clist_t *clist;

static isc_mutex_t fastrpz_mutex;

static void
fastrpz_lock(void *mutex0) {
	isc_mutex_t *mutex = mutex0;

	LOCK(mutex);
}

static void
fastrpz_unlock(void *mutex0) {
	isc_mutex_t *mutex = mutex0;

	UNLOCK(mutex);
}

static void
fastrpz_mutex_destroy(void *mutex0) {
	isc_mutex_t *mutex = mutex0;

	DESTROYLOCK(mutex);
}

static void
fastrpz_log_fnc(librpz_log_level_t level, void *ctxt, const char *buf) {
	int isc_level;

	UNUSED(ctxt);

	/* Setting librpz_log_level in the configuration overrides the
	 * BIND9 logging levels. */
	if (level > LIBRPZ_LOG_TRACE1 &&
	    level <= librpz->log_level_val(LIBRPZ_LOG_INVALID))
		level = LIBRPZ_LOG_TRACE1;

	switch(level) {
	case LIBRPZ_LOG_FATAL:
	case LIBRPZ_LOG_ERROR:		/* errors */
	default:
		isc_level = DNS_RPZ_ERROR_LEVEL;
		break;

	case LIBRPZ_LOG_TRACE1:		/* big events such as dnsrpzd starts */
		isc_level = DNS_RPZ_INFO_LEVEL;
		break;

	case LIBRPZ_LOG_TRACE2:		/* smaller dnsrpzd zone transfers */
		isc_level = DNS_RPZ_DEBUG_LEVEL1;
		break;

	case LIBRPZ_LOG_TRACE3:		/* librpz hits */
		isc_level = DNS_RPZ_DEBUG_LEVEL2;
		break;

	case LIBRPZ_LOG_TRACE4:		/* librpz lookups */
		isc_level = DNS_RPZ_DEBUG_LEVEL3;
		break;
	}
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_RPZ, DNS_LOGMODULE_RBTDB,
		      isc_level, "fastrpz: %s", buf);
}

/*
 * Start Fastrpz for the entire server.
 *	This is not thread safe, but it is called by a single thread.
 */
isc_result_t
dns_fastrpz_server_create(void) {
	librpz_emsg_t emsg;
	isc_result_t result;

	INSIST(clist == NULL);
	INSIST(librpz == NULL);
	INSIST(librpz_handle == NULL);

	/*
	 * Notice if librpz is available.
	 */
	librpz = librpz_lib_open(&librpz_lib_open_emsg,
				 &librpz_handle, FASTRPZ_LIBRPZ_PATH);
	/*
	 * Stop now without complaining if librpz is not available.
	 * Complain later if and when librpz is needed for a view with
	 * "fastrpz-enable yse" (including the default view).
	 */
	if (librpz == NULL)
		return (ISC_R_SUCCESS);

	result = isc_mutex_init(&fastrpz_mutex);
	if (result != ISC_R_SUCCESS)
		return (result);

	librpz->set_log(&fastrpz_log_fnc, NULL);

	clist = librpz->clist_create(&emsg, fastrpz_lock, fastrpz_unlock,
				     fastrpz_mutex_destroy, &fastrpz_mutex,
				     dns_lctx);
	if (clist == NULL) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_RPZ,
			      DNS_LOGMODULE_RBTDB, DNS_RPZ_ERROR_LEVEL,
			      "fastrpz: %s", emsg.c);
		return (ISC_R_NOMEMORY);
	}
	return (ISC_R_SUCCESS);
}

/*
 * Stop Fastrpz for the entire server.
 *	This is not thread safe.
 */
void
dns_fastrpz_server_destroy(void) {
	if (clist != NULL)
		librpz->clist_detach(&clist);

#ifdef LIBRPZ_USE_DLOPEN
	if (librpz != NULL) {
		INSIST(librpz_handle != NULL);
		if (dlclose(librpz_handle) != 0)
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_RPZ,
				      DNS_LOGMODULE_RBTDB, DNS_RPZ_ERROR_LEVEL,
				      "fastrpz: dlclose(): %s", dlerror());
		librpz_handle = NULL;
	}
#endif
}

/*
 * Ready Fastrpz for a view.
 */
isc_result_t
dns_fastrpz_view_init(dns_rpz_zones_t *new, char *fast_cstr) {
	librpz_emsg_t emsg;

	isc_log_write(dns_lctx, DNS_LOGCATEGORY_RPZ,
		      DNS_LOGMODULE_RBTDB, DNS_RPZ_DEBUG_LEVEL3,
		      "fastrpz configuration \"%s\"", fast_cstr);

	new->fast_client = librpz->client_create(&emsg, clist,
						 fast_cstr, ISC_FALSE);
	if (new->fast_client == NULL) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_RPZ,
			      DNS_LOGMODULE_RBTDB, DNS_RPZ_ERROR_LEVEL,
			      "librpz->client_create(): %s", emsg.c);
		new->p.fastrpz_enabled = ISC_FALSE;
		return (ISC_R_FAILURE);
	}

	new->p.fastrpz_enabled = ISC_TRUE;
	return (ISC_R_SUCCESS);
}

/*
 * Connect to and start the Fastrpz daemon, dnsrpzd.
 */
isc_result_t
dns_fastrpz_connect(dns_rpz_zones_t *rpzs) {
	librpz_emsg_t emsg;

	if (rpzs == NULL || !rpzs->p.fastrpz_enabled)
		return (ISC_R_SUCCESS);

	/*
	 * Fail only if we failed to link to librpz.
	 */
	if (librpz == NULL) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_RPZ,
			      DNS_LOGMODULE_RBTDB, DNS_RPZ_ERROR_LEVEL,
			      "librpz->connect(): %s", librpz_lib_open_emsg.c);
		return (ISC_R_FAILURE);
	}

	if (!librpz->connect(&emsg, rpzs->fast_client, true)) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_RPZ,
			      DNS_LOGMODULE_RBTDB, DNS_RPZ_ERROR_LEVEL,
			      "librpz->connect(): %s", emsg.c);
		return (ISC_R_SUCCESS);
	}

	isc_log_write(dns_lctx, DNS_LOGCATEGORY_RPZ, DNS_LOGMODULE_RBTDB,
		      DNS_RPZ_INFO_LEVEL, "fastrpz: librpz version %s",
		      librpz->version);

	return (ISC_R_SUCCESS);
}

/*
 * Get ready to try RPZ rewriting.
 */
isc_result_t
dns_fastrpz_rewrite_init(librpz_emsg_t *emsg, dns_rpz_st_t *st,
			 dns_rpz_zones_t *rpzs, const dns_name_t *qname,
			 isc_mem_t *mctx, isc_boolean_t have_rd)
{
	fastdb_t *fastdb;

	fastdb = isc_mem_get(mctx, sizeof(*fastdb));
	if (fastdb == NULL) {
		strlcpy(emsg->c, "no memory", sizeof(emsg->c));
		return (ISC_R_NOMEMORY);
	}
	memset(fastdb, 0, sizeof(*fastdb));

	if (!librpz->rsp_create(emsg, &fastdb->rsp, NULL,
				rpzs->fast_client, have_rd, false)) {
		isc_mem_put(mctx, fastdb, sizeof(*fastdb));
		return (DNS_R_SERVFAIL);
	}
	if (fastdb->rsp == NULL) {
		isc_mem_put(mctx, fastdb, sizeof(*fastdb));
		return (DNS_R_DISALLOWED);
	}

	fastdb->common.magic = DNS_DB_MAGIC;
	fastdb->common.impmagic = FASTDB_MAGIC;
	fastdb->common.methods = &fastdb_db_methods;
	fastdb->common.rdclass = dns_rdataclass_in;
	dns_name_init(&fastdb->common.origin, NULL);
	isc_mem_attach(mctx, &fastdb->common.mctx);

	fastdb->ref_cnt = 1;
	fastdb->qname = qname;

	st->fastdb = &fastdb->common;
	return (ISC_R_SUCCESS);
}

/*
 * Convert a fastrpz policy to a classic BIND9 RPZ policy.
 */
dns_rpz_policy_t
dns_fastrpz_2policy(librpz_policy_t fast_policy) {
	switch (fast_policy) {
	case LIBRPZ_POLICY_UNDEFINED:
		return (DNS_RPZ_POLICY_MISS);
	case LIBRPZ_POLICY_PASSTHRU:
		return (DNS_RPZ_POLICY_PASSTHRU);
	case LIBRPZ_POLICY_DROP:
		return (DNS_RPZ_POLICY_DROP);
	case LIBRPZ_POLICY_TCP_ONLY:
		return (DNS_RPZ_POLICY_TCP_ONLY);
	case LIBRPZ_POLICY_NXDOMAIN:
		return (DNS_RPZ_POLICY_NXDOMAIN);
	case LIBRPZ_POLICY_NODATA:
		return (DNS_RPZ_POLICY_NODATA);
	case LIBRPZ_POLICY_RECORD:
	case LIBRPZ_POLICY_CNAME:
		return (DNS_RPZ_POLICY_RECORD);

	case LIBRPZ_POLICY_DELETED:
	case LIBRPZ_POLICY_GIVEN:
	case LIBRPZ_POLICY_DISABLED:
	default:
		INSIST(0);
	}
}

/*
 * Convert a fastrpz trigger to a classic BIND9 RPZ rewrite or trigger type.
 */
dns_rpz_type_t
dns_fastrpz_trig2type(librpz_trig_t trig) {
	switch (trig) {
	case LIBRPZ_TRIG_BAD:
	default:
		return (DNS_RPZ_TYPE_BAD);
	case LIBRPZ_TRIG_CLIENT_IP:
		return (DNS_RPZ_TYPE_CLIENT_IP);
	case LIBRPZ_TRIG_QNAME:
		return (DNS_RPZ_TYPE_QNAME);
	case LIBRPZ_TRIG_IP:
		return (DNS_RPZ_TYPE_IP);
	case LIBRPZ_TRIG_NSDNAME:
		return (DNS_RPZ_TYPE_NSDNAME);
	case LIBRPZ_TRIG_NSIP:
		return (DNS_RPZ_TYPE_NSIP);
	}
}

/*
 * Convert a classic BIND9 RPZ rewrite or trigger type to a librpz trigger type.
 */
librpz_trig_t
dns_fastrpz_type2trig(dns_rpz_type_t type) {
	switch (type) {
	case DNS_RPZ_TYPE_BAD:
	default:
		return (LIBRPZ_TRIG_BAD);
	case DNS_RPZ_TYPE_CLIENT_IP:
		return (LIBRPZ_TRIG_CLIENT_IP);
	case DNS_RPZ_TYPE_QNAME:
		return (LIBRPZ_TRIG_QNAME);
	case DNS_RPZ_TYPE_IP:
		return (LIBRPZ_TRIG_IP);
	case DNS_RPZ_TYPE_NSDNAME:
		return (LIBRPZ_TRIG_NSDNAME);
	case DNS_RPZ_TYPE_NSIP:
		return (LIBRPZ_TRIG_NSIP);
	}
}

static void
fastdb_attach(dns_db_t *source, dns_db_t **targetp) {
	fastdb_t *fastdb = (fastdb_t *)source;

	REQUIRE(VALID_FASTDB(fastdb));

	/*
	 * Use a simple count because only one thread uses any single fastdb_t
	 */
	++fastdb->ref_cnt;
	*targetp = source;
}

static void
fastdb_detach(dns_db_t **dbp) {
	fastdb_t *fastdb = (fastdb_t *)*dbp;

	REQUIRE(VALID_FASTDB(fastdb));
	REQUIRE(fastdb->ref_cnt > 0);

	*dbp = NULL;

	/*
	 * Simple count because only one thread uses a fastdb_t.
	 */
	if (--fastdb->ref_cnt != 0)
		return;

	librpz->rsp_detach(&fastdb->rsp);
	fastdb->common.impmagic = 0;
	isc_mem_putanddetach(&fastdb->common.mctx, fastdb, sizeof(*fastdb));
}

static void
fastdb_attachnode(dns_db_t *db, dns_dbnode_t *source, dns_dbnode_t **targetp) {
	fastdb_t *fastdb = (fastdb_t *)db;

	REQUIRE(VALID_FASTDB(fastdb));
	REQUIRE(targetp != NULL && *targetp == NULL);
	REQUIRE(source == &fastdb->origin_node ||
		source == &fastdb->data_node);

	/*
	 * Simple count because only one thread uses a fastdb_t.
	 */
	++fastdb->ref_cnt;
	*targetp = source;
}

static void
fastdb_detachnode(dns_db_t *db, dns_dbnode_t **targetp) {
	fastdb_t *fastdb = (fastdb_t *)db;

	REQUIRE(VALID_FASTDB(fastdb));
	REQUIRE(*targetp == &fastdb->origin_node ||
		*targetp == &fastdb->data_node);

	*targetp = NULL;
	fastdb_detach(&db);
}

static isc_result_t
fastdb_findnode(dns_db_t *db, const dns_name_t *name, isc_boolean_t create,
		dns_dbnode_t **nodep)
{
	fastdb_t *fastdb = (fastdb_t *)db;
	dns_db_t *dbp;

	REQUIRE(VALID_FASTDB(fastdb));
	REQUIRE(nodep != NULL && *nodep == NULL);
	REQUIRE(!create);

	/*
	 * A fake/shim fastdb has two nodes.
	 * One is the origin to support query_addsoa() in bin/named/query.c.
	 * The other contains rewritten RRs.
	 */
	if (dns_name_equal(name, &db->origin))
		*nodep = &fastdb->origin_node;
	else
		*nodep = &fastdb->data_node;
	dbp = NULL;
	fastdb_attach(db, &dbp);

	return (ISC_R_SUCCESS);
}

static void
fastdb_bind_rdataset(dns_rdataset_t *rdataset, uint count, librpz_idx_t next_rr,
		     dns_rdatatype_t type, uint16_t class, uint32_t ttl,
		     fastdb_t *fastdb)
{
	dns_db_t *dbp;

	INSIST(rdataset->methods == NULL);      /* We must be disassociated. */
	REQUIRE(type != dns_rdatatype_none);

	rdataset->methods = &fastdb_rdataset_methods;
	rdataset->rdclass = class;
	rdataset->type = type;
	rdataset->ttl = ttl;
	dbp = NULL;
	dns_db_attach(&fastdb->common, &dbp);
	RD_DB(rdataset) = dbp;
	RD_COUNT(rdataset) = count;
	RD_NEXT_RR(rdataset) = next_rr;
	RD_CUR_RR(rdataset) = NULL;
}

static isc_result_t
fastdb_bind_soa(dns_rdataset_t *rdataset, fastdb_t *fastdb)
{
	uint32_t ttl;
	librpz_emsg_t emsg;

	if (!librpz->rsp_soa(&emsg, &ttl, NULL, NULL,
			     &fastdb->result, fastdb->rsp)) {
		librpz->log(LIBRPZ_LOG_ERROR, NULL, "%s", emsg.c);
		return (DNS_R_SERVFAIL);
	}
	fastdb_bind_rdataset(rdataset, 1, LIBRPZ_IDX_BAD, dns_rdatatype_soa,
			     dns_rdataclass_in, ttl, fastdb);
	return (ISC_R_SUCCESS);
}

/*
 * Forge an rdataset of the desired type from a librpz result.
 * This is written for simplicity instead of speed, because RPZ rewriting
 * should be rare compared to normal BIND operations.
 */
static isc_result_t
fastdb_findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		    dns_rdatatype_t type, dns_rdatatype_t covers,
		    isc_stdtime_t now, dns_rdataset_t *rdataset,
		    dns_rdataset_t *sigrdataset)
{
	fastdb_t *fastdb = (fastdb_t *)db;
	dns_rdatatype_t foundtype;
	dns_rdataclass_t class;
	uint32_t ttl;
	uint count;
	librpz_emsg_t emsg;

	UNUSED(version);
	UNUSED(covers);
	UNUSED(now);
	UNUSED(sigrdataset);

	REQUIRE(VALID_FASTDB(fastdb));

	if (node == &fastdb->origin_node) {
		if (type == dns_rdatatype_any)
			return (ISC_R_SUCCESS);
		if (type == dns_rdatatype_soa)
			return (fastdb_bind_soa(rdataset, fastdb));
		return (DNS_R_NXRRSET);
	}

	REQUIRE(node == &fastdb->data_node);

	switch (fastdb->result.policy) {
	case LIBRPZ_POLICY_UNDEFINED:
	case LIBRPZ_POLICY_DELETED:
	case LIBRPZ_POLICY_PASSTHRU:
	case LIBRPZ_POLICY_DROP:
	case LIBRPZ_POLICY_TCP_ONLY:
	case LIBRPZ_POLICY_GIVEN:
	case LIBRPZ_POLICY_DISABLED:
	default:
		librpz->log(LIBRPZ_LOG_ERROR, NULL,
			    "impossible fastrpz policy %d at %s:%d",
			    fastdb->result.policy, __FILE__, __LINE__);
		return (DNS_R_SERVFAIL);

	case LIBRPZ_POLICY_NXDOMAIN:
		return (DNS_R_NXDOMAIN);

	case LIBRPZ_POLICY_NODATA:
		return (DNS_R_NXRRSET);

	case LIBRPZ_POLICY_RECORD:
	case LIBRPZ_POLICY_CNAME:
		break;
	}

	if (type == dns_rdatatype_soa)
		return (fastdb_bind_soa(rdataset, fastdb));

	/*
	 * There is little to do for an ANY query.
	 */
	if (type == dns_rdatatype_any)
		return (ISC_R_SUCCESS);

	/*
	 * Reset to the start of the RRs.
	 * This function is only used after a policy has been chosen,
	 * and so without caring whether it is after recursion.
	 */
	if (!librpz->rsp_result(&emsg, &fastdb->result, true, fastdb->rsp)) {
		librpz->log(LIBRPZ_LOG_ERROR, NULL, "%s", emsg.c);
		return (DNS_R_SERVFAIL);
	}
	if (!librpz->rsp_rr(&emsg, &foundtype, &class, &ttl, NULL,
			    &fastdb->result, fastdb->qname->ndata,
			    fastdb->qname->length, fastdb->rsp)) {
		librpz->log(LIBRPZ_LOG_ERROR, NULL, "%s", emsg.c);
		return (DNS_R_SERVFAIL);
	}
	REQUIRE(foundtype != dns_rdatatype_none);

	/*
	 * Ho many of the target RR type are available?
	 */
	count = 0;
	do {
		if (type == foundtype || type == dns_rdatatype_any)
			++count;

		if (!librpz->rsp_rr(&emsg, &foundtype, NULL, NULL, NULL,
				    &fastdb->result, fastdb->qname->ndata,
				    fastdb->qname->length, fastdb->rsp)) {
			librpz->log(LIBRPZ_LOG_ERROR, NULL, "%s", emsg.c);
			return (DNS_R_SERVFAIL);
		}
	} while (foundtype != dns_rdatatype_none);
	if (count == 0)
		return (DNS_R_NXRRSET);
	fastdb_bind_rdataset(rdataset, count, fastdb->result.next_rr,
			     type, class, ttl, fastdb);
	return (ISC_R_SUCCESS);
}

static isc_result_t
fastdb_finddb(dns_db_t *db, const dns_name_t *name, dns_dbversion_t *version,
	      dns_rdatatype_t type, unsigned int options, isc_stdtime_t now,
	      dns_dbnode_t **nodep, dns_name_t *foundname,
	      dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset)
{
	dns_dbnode_t *node;
	isc_result_t result;

	UNUSED(version);
	UNUSED(options);
	UNUSED(now);
	UNUSED(sigrdataset);

	if (nodep == NULL) {
		node = NULL;
		nodep = &node;
	}
	fastdb_findnode(db, name, false, nodep);
	result = dns_name_copy(name, foundname, NULL);
	if (result != ISC_R_SUCCESS)
		return (result);
	return (fastdb_findrdataset(db, *nodep, NULL, type, 0, 0,
				    rdataset, sigrdataset));
}

static isc_result_t
fastdb_allrdatasets(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		    isc_stdtime_t now, dns_rdatasetiter_t **iteratorp)
{
	fastdb_t *fastdb = (fastdb_t *)db;
	fastdb_rdatasetiter_t *fastdb_iter;

	UNUSED(version);
	UNUSED(now);

	REQUIRE(VALID_FASTDB(fastdb));
	REQUIRE(node == &fastdb->origin_node || node == &fastdb->data_node);

	fastdb_iter = isc_mem_get(fastdb->common.mctx, sizeof(*fastdb_iter));
	if (fastdb_iter == NULL)
		return (ISC_R_NOMEMORY);

	memset(fastdb_iter, 0, sizeof(*fastdb_iter));
	fastdb_iter->common.magic = DNS_RDATASETITER_MAGIC;
	fastdb_iter->common.methods = &fastdb_rdatasetiter_methods;
	fastdb_iter->common.db = db;
	fastdb_attachnode(db, node, &fastdb_iter->common.node);

	*iteratorp = &fastdb_iter->common;

	return (ISC_R_SUCCESS);
}

static isc_boolean_t
fastdb_issecure(dns_db_t *db) {
	UNUSED(db);

	return (ISC_FALSE);
}

static isc_result_t
fastdb_getoriginnode(dns_db_t *db, dns_dbnode_t **nodep) {
	fastdb_t *fastdb = (fastdb_t *)db;

	REQUIRE(VALID_FASTDB(fastdb));
	REQUIRE(nodep != NULL && *nodep == NULL);

	fastdb_attachnode(db, &fastdb->origin_node, nodep);
	return (ISC_R_SUCCESS);
}

static void
fastdb_rdataset_disassociate(dns_rdataset_t *rdataset) {
	dns_db_t *db;

	/*
	 * Detach the last RR delivered.
	 */
	if (RD_CUR_RR(rdataset) != NULL) {
		free(RD_CUR_RR(rdataset));
		RD_CUR_RR(rdataset) = NULL;
	}

	db = RD_DB(rdataset);
	RD_DB(rdataset) = NULL;
	dns_db_detach(&db);
}

static isc_result_t
fastdb_rdataset_next(dns_rdataset_t *rdataset) {
	fastdb_t *fastdb;
	uint16_t type;
	dns_rdataclass_t class;
	librpz_rr_t *rr;
	librpz_emsg_t emsg;

	fastdb = RD_DB(rdataset);

	/*
	 * Detach the previous RR.
	 */
	if (RD_CUR_RR(rdataset) != NULL) {
		free(RD_CUR_RR(rdataset));
		RD_CUR_RR(rdataset) = NULL;
	}

	/*
	 * Get the next RR of the specified type.
	 * SOAs differ.
	 */
	if (rdataset->type == dns_rdatatype_soa) {
		if (RD_NEXT_RR(rdataset) == LIBRPZ_IDX_NULL)
			return (ISC_R_NOMORE);
		RD_NEXT_RR(rdataset) = LIBRPZ_IDX_NULL;
		if (!librpz->rsp_soa(&emsg, NULL, &rr, NULL,
				     &fastdb->result, fastdb->rsp)) {
			librpz->log(LIBRPZ_LOG_ERROR, NULL, "%s", emsg.c);
			return (DNS_R_SERVFAIL);
		}
		RD_CUR_RR(rdataset) = rr;
		return (ISC_R_SUCCESS);
	}

	fastdb->result.next_rr = RD_NEXT_RR(rdataset);
	for (;;) {
		if (!librpz->rsp_rr(&emsg, &type, &class, NULL, &rr,
				    &fastdb->result, fastdb->qname->ndata,
				    fastdb->qname->length, fastdb->rsp)) {
			librpz->log(LIBRPZ_LOG_ERROR, NULL, "%s", emsg.c);
			return (DNS_R_SERVFAIL);
		}
		if (rdataset->type == type &&
		    rdataset->rdclass == class) {
			RD_CUR_RR(rdataset) = rr;
			RD_NEXT_RR(rdataset) = fastdb->result.next_rr;
			return (ISC_R_SUCCESS);
		}
		if (type == dns_rdatatype_none)
			return (ISC_R_NOMORE);
		free(rr);
	}
}

static isc_result_t
fastdb_rdataset_first(dns_rdataset_t *rdataset) {
	fastdb_t *fastdb;
	librpz_emsg_t emsg;

	fastdb = RD_DB(rdataset);
	REQUIRE(VALID_FASTDB(fastdb));

	if (RD_CUR_RR(rdataset) != NULL) {
		free(RD_CUR_RR(rdataset));
		RD_CUR_RR(rdataset) = NULL;
	}

	if (!librpz->rsp_result(&emsg, &fastdb->result, true, fastdb->rsp)) {
		librpz->log(LIBRPZ_LOG_ERROR, NULL, "%s", emsg.c);
		return (DNS_R_SERVFAIL);
	}
	if (rdataset->type == dns_rdatatype_soa)
		RD_NEXT_RR(rdataset) = LIBRPZ_IDX_BAD;
	else
		RD_NEXT_RR(rdataset) = fastdb->result.next_rr;

	return (fastdb_rdataset_next(rdataset));
}

static void
fastdb_rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {
	fastdb_t *fastdb;
	librpz_rr_t *rr;
	isc_region_t r;

	fastdb = RD_DB(rdataset);
	REQUIRE(VALID_FASTDB(fastdb));
	rr = RD_CUR_RR(rdataset);
	REQUIRE(rr != NULL);

	r.length = ntohs(rr->rdlength);
	r.base = rr->rdata;
	dns_rdata_fromregion(rdata, ntohs(rr->class), ntohs(rr->type), &r);
}

static void
fastdb_rdataset_clone(dns_rdataset_t *source, dns_rdataset_t *target) {
	fastdb_t *fastdb;
	dns_db_t *dbp;

	INSIST(!ISC_LINK_LINKED(target, link));
	*target = *source;
	ISC_LINK_INIT(target, link);
	fastdb = RD_DB(source);
	REQUIRE(VALID_FASTDB(fastdb));
	dbp = NULL;
	dns_db_attach(&fastdb->common, &dbp);
	RD_DB(target) = dbp;
	RD_CUR_RR(target) = NULL;
	RD_NEXT_RR(target) = LIBRPZ_IDX_NULL;
}

static unsigned int
fastdb_rdataset_count(dns_rdataset_t *rdataset) {
	fastdb_t *fastdb;

	fastdb = RD_DB(rdataset);
	REQUIRE(VALID_FASTDB(fastdb));

	return (RD_COUNT(rdataset));
}

static void
fastdb_rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp) {
	fastdb_t *fastdb;
	dns_rdatasetiter_t *iterator;
	isc_mem_t *mctx;

	iterator = *iteratorp;
	fastdb = (fastdb_t *)iterator->db;
	REQUIRE(VALID_FASTDB(fastdb));

	mctx = iterator->db->mctx;
	dns_db_detachnode(iterator->db, &iterator->node);
	isc_mem_put(mctx, iterator, sizeof(fastdb_rdatasetiter_t));
	*iteratorp = NULL;
}

static isc_result_t
fastdb_rdatasetiter_next(dns_rdatasetiter_t *iter) {
	fastdb_t *fastdb;
	fastdb_rdatasetiter_t *fastdb_iter;
	dns_rdatatype_t next_type, type;
	dns_rdataclass_t next_class, class;
	uint32_t ttl;
	librpz_emsg_t emsg;

	fastdb = (fastdb_t *)iter->db;
	REQUIRE(VALID_FASTDB(fastdb));
	fastdb_iter = (fastdb_rdatasetiter_t *)iter;

	/*
	 * This function is only used after a policy has been chosen,
	 * and so without caring whether it is after recursion.
	 */
	if (!librpz->rsp_result(&emsg, &fastdb->result, true, fastdb->rsp)) {
		librpz->log(LIBRPZ_LOG_ERROR, NULL, "%s", emsg.c);
		return (DNS_R_SERVFAIL);
	}
	/*
	 * Find the next class and type after the current class and type
	 * among the RRs in current result.
	 * As a side effect, count the number of those RRs.
	 */
	fastdb_iter->count = 0;
	next_class = dns_rdataclass_reserved0;
	next_type = dns_rdatatype_none;
	for (;;) {
		if (!librpz->rsp_rr(&emsg, &type, &class, &ttl,
				    NULL, &fastdb->result, fastdb->qname->ndata,
				    fastdb->qname->length, fastdb->rsp)) {
			librpz->log(LIBRPZ_LOG_ERROR, NULL, "%s", emsg.c);
			return (DNS_R_SERVFAIL);
		}
		if (type == dns_rdatatype_none) {
			if (next_type == dns_rdatatype_none)
				return (ISC_R_NOMORE);
			fastdb_iter->type = next_type;
			fastdb_iter->class = next_class;
			return (ISC_R_SUCCESS);
		}
		/*
		 * Skip RRs with the current class and type or before.
		 */
		if (fastdb_iter->class > class ||
		    (fastdb_iter->class = class && fastdb_iter->type >= type))
			continue;
		if (next_type == dns_rdatatype_none ||
		    next_class > class ||
		    (next_class == class && next_type > type)) {
			/*
			 * This is the first of a subsequent class and type.
			 */
			next_type = type;
			next_class = class;
			fastdb_iter->ttl = ttl;
			fastdb_iter->count = 1;
			fastdb_iter->next_rr = fastdb->result.next_rr;
		} else if (next_type == type && next_class == class) {
			++fastdb_iter->count;
		}
	}
}

static isc_result_t
fastdb_rdatasetiter_first(dns_rdatasetiter_t *iterator) {
	fastdb_t *fastdb;
	fastdb_rdatasetiter_t *fastdb_iter;

	fastdb = (fastdb_t *)iterator->db;
	REQUIRE(VALID_FASTDB(fastdb));
	fastdb_iter = (fastdb_rdatasetiter_t *)iterator;

	fastdb_iter->type = dns_rdatatype_none;
	fastdb_iter->class = dns_rdataclass_reserved0;
	return (fastdb_rdatasetiter_next(iterator));
}

static void
fastdb_rdatasetiter_current(dns_rdatasetiter_t *iterator,
			    dns_rdataset_t *rdataset)
{
	fastdb_t *fastdb;
	fastdb_rdatasetiter_t *fastdb_iter;

	fastdb = (fastdb_t *)iterator->db;
	REQUIRE(VALID_FASTDB(fastdb));
	fastdb_iter = (fastdb_rdatasetiter_t *)iterator;
	REQUIRE(fastdb_iter->type != dns_rdatatype_none);

	fastdb_bind_rdataset(rdataset,
			     fastdb_iter->count, fastdb_iter->next_rr,
			     fastdb_iter->type, fastdb_iter->class,
			     fastdb_iter->ttl, fastdb);
}

static dns_dbmethods_t fastdb_db_methods = {
	fastdb_attach,
	fastdb_detach,
	NULL,			/* beginload */
	NULL,			/* endload */
	NULL,			/* serialize */
	NULL,			/* dump */
	NULL,			/* currentversion */
	NULL,			/* newversion */
	NULL,			/* attachversion */
	NULL,			/* closeversion */
	fastdb_findnode,
	fastdb_finddb,
	NULL,			/* findzonecut */
	fastdb_attachnode,
	fastdb_detachnode,
	NULL,			/* expirenode */
	NULL,			/* printnode */
	NULL,			/* createiterator */
	fastdb_findrdataset,
	fastdb_allrdatasets,
	NULL,			/* addrdataset */
	NULL,			/* subtractrdataset */
	NULL,			/* deleterdataset */
	fastdb_issecure,
	NULL,			/* nodecount */
	NULL,			/* ispersistent */
	NULL,			/* overmem */
	NULL,			/* settask */
	fastdb_getoriginnode,
	NULL,			/* transfernode */
	NULL,			/* getnsec3parameters */
	NULL,			/* findnsec3node */
	NULL,			/* setsigningtime */
	NULL,			/* getsigningtime */
	NULL,			/* resigned */
	NULL,			/* isdnssec */
	NULL,			/* getrrsetstats */
	NULL,			/* rpz_attach */
	NULL,			/* rpz_ready */
	NULL,			/* findnodeext */
	NULL,			/* findext */
	NULL,			/* setcachestats */
	NULL,			/* hashsize */
	NULL,			/* nodefullname */
	NULL			/* getsize */
};

static dns_rdatasetmethods_t fastdb_rdataset_methods = {
	fastdb_rdataset_disassociate,
	fastdb_rdataset_first,
	fastdb_rdataset_next,
	fastdb_rdataset_current,
	fastdb_rdataset_clone,
	fastdb_rdataset_count,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

static dns_rdatasetitermethods_t fastdb_rdatasetiter_methods = {
	fastdb_rdatasetiter_destroy,
	fastdb_rdatasetiter_first,
	fastdb_rdatasetiter_next,
	fastdb_rdatasetiter_current
};

#endif /* USE_FASTRPZ */
