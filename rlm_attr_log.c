/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Partially based and insipired on rlm_detail and rlm_rest */

/**
 * $Id: 3b250c4f890164d0e35f54e9d9319f280942a0df $
 * @file rlm_attr_log.c
 * @brief Log full RADIUS packets via UDP, serialized as JSON
 *
 * @copyright 2013-2015 Quarantainenet
 * @copyright 2013-2015 Justin Ossevoort \<justin@quarantainenet.nl\>
 */
RCSID("$Id: 3b250c4f890164d0e35f54e9d9319f280942a0df $")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

typedef struct rlm_attr_log_t {
	fr_hash_table_t *ht; /* When certain attributes should be suppressed */
	uint32_t log_size;   /* Maximim size of the log message to generate */
	char const *prefix;  /* Prefix to include before every log message */
	fr_ipaddr_t ip;      /* IP address to send logging to */
	uint16_t port;       /* UDP port to send logging to */

	int sockfd;
} rlm_attr_log_t;

static const CONF_PARSER module_config[] = {
	{ "log_size", FR_CONF_OFFSET(PW_TYPE_INTEGER,   rlm_attr_log_t, log_size), "65400"     },
	{ "prefix",   FR_CONF_OFFSET(PW_TYPE_STRING,    rlm_attr_log_t, prefix  ), "Radius: " },
	{ "ip",       FR_CONF_OFFSET(PW_TYPE_IPV4_ADDR, rlm_attr_log_t, ip      ), "127.0.0.1" },
	{ "port",     FR_CONF_OFFSET(PW_TYPE_SHORT,     rlm_attr_log_t, port    ), "1514"      },

	{ NULL, -1, 0, NULL, NULL } /* end the list */
};

static uint32_t attr_hash(void const *data)
{
	DICT_ATTR const *da = data;
	return fr_hash(&da, sizeof(da));
}

static int attr_cmp(void const *a, void const *b)
{
	DICT_ATTR const *one = a;
	DICT_ATTR const *two = b;

	return one - two;
}

static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	DEBUG3("rlm_attr_log: Initializing");

	rlm_attr_log_t *inst = instance;
	inst->sockfd = -1;
	inst->ht = NULL;

	/*
	 * Setup logging socket
	 */

	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_port   = htons(inst->port),
		.sin_addr   = inst->ip.ipaddr.ip4addr
	};

	int r = inst->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (r == -1) {
		ERROR("rlm_attr_log: Failed to create logging socket: %s", fr_strerror());
		goto err_out;
	}
	r = connect(inst->sockfd, &sin, sizeof(sin));
	if (r == -1) {
		ERROR("rlm_attr_log: Failed to connect logging socket: %s", fr_strerror());
		goto err_out;
	}

	/*
	 * Suppress certain attributes.
	 *
	 * Code from 'rlm_detail'
	 */
	CONF_SECTION *cs = cf_section_sub_find(conf, "suppress");
	if (cs) {
		CONF_ITEM *ci;

		inst->ht = fr_hash_table_create(attr_hash, attr_cmp, NULL);

		for (ci = cf_item_find_next(cs, NULL);
		     ci != NULL;
		     ci = cf_item_find_next(cs, ci)) {
			char const *attr;
			DICT_ATTR const *da;

			if (!cf_item_is_pair(ci)) continue;

			attr = cf_pair_attr(cf_item_to_pair(ci));
			if (!attr) continue; /* pair-anoia */

			da = dict_attrbyname(attr);
			if (!da) {
				cf_log_err_cs(conf, "No such attribute '%s'", attr);
				goto err_out;
			}

			/*
			 * Be kind to minor mistakes.
			 */
			if (fr_hash_table_finddata(inst->ht, da)) {
				WARN("rlm_attr_log: Ignoring duplicate entry '%s'", attr);
				continue;
			}


			if (!fr_hash_table_insert(inst->ht, da)) {
				ERROR("rlm_attr_log: Failed inserting '%s' into suppression table", attr);
				goto err_out;
			}

			DEBUG("rlm_attr_log: '%s' suppressed, will not appear in detail output", attr);
		}

		/*
		 * If we didn't suppress anything, delete the hash table.
		 */
		if (fr_hash_table_num_elements(inst->ht) == 0) {
			fr_hash_table_free(inst->ht);
			inst->ht = NULL;
		}
	}

	DEBUG2("rlm_attr_log: Initialized");
	return 0;

err_out:
	if (inst->ht) {
		fr_hash_table_free(inst->ht);
		inst->ht = NULL;
	}
	if (inst->sockfd >= 0) {
		close(inst->sockfd);
		inst->sockfd = -1;
	}

	ERROR("rlm_attr_log: Initialisation failed");
	return -1;
}

/* Based upon rest_encode_json() from 'rlm_rest/rest.c', though heavily simplified */
static int log_attrs_json(rlm_attr_log_t *inst, UNUSED REQUEST *request, VALUE_PAIR *vps, const char *packet_type, char *out, size_t size)
{
	vp_cursor_t cursor;
	DICT_VALUE *dv;
	VALUE_PAIR *vp, *next;
	char *p = out;           /* Position in buffer */
	char *encoded = p;       /* Position in buffer of last fully encoded attribute or value */
	size_t freespace = size; /* Size left in buffer */
	char const *type;        /* Used when determining attribute value types */
	int truncated = 0;
	size_t len;

	{ /* Begin packet hash */
		len = snprintf(p, freespace - 1 /* for closing curly bracket */, "\"%s\":{", packet_type);
		if (len > freespace - 1)
			return 0;

		p += len;
		freespace -= len + 1 /* Reserve 1 byte for the closing curly bracket */;
		encoded = p;
	}

	/* Make sure multi-valued attributes are grouped together */
	fr_pair_list_sort(&vps, fr_pair_cmp_by_da_tag);

	fr_cursor_init(&cursor, &vps);
	next_attr: for (;;) {
		vp = fr_cursor_current(&cursor);

		/* Encoded all VPs */
		if (!vp) break;

		/* Suppress certain attributes */
		if (inst->ht && fr_hash_table_finddata(inst->ht, vp->da)) {
			/* Skip possible more multi-values of this attribute and advance cursor */
			while ((next = fr_cursor_next(&cursor)) && (vp->da == next->da)) vp = next;
			continue;
		}

		/* Lookup possibly dictionary mapped values (see also 'src/lib/print.c') */
		switch (vp->da->type) {
			case PW_TYPE_INTEGER:
			case PW_TYPE_BYTE:
			case PW_TYPE_SHORT:
				dv = dict_valbyattr(vp->da->attr, vp->da->vendor, vp->data.integer);
				break;

			default:
				dv = NULL;
		}

		/* New attribute: Write name, type and beginning of value array */
		/* (while reservering 2 bytes for closing bracket and curly bracket) */
		type = ( dv ? "mapped" : fr_int2str(dict_attr_types, vp->da->type, "<INVALID>") );
		len = snprintf(p, freespace - 2, "\"%s\":{\"type\":\"%s\",\"value\":[", vp->da->name, type);
		if (len > freespace - 2) {
			/* Skip possible more multi-values of this attribute and advance cursor */
			while ((next = fr_cursor_next(&cursor)) && (vp->da == next->da)) vp = next;
			truncated = 1;
			continue;
		}
		p += len;
		freespace -= len  + 2 /* Reserve 2 bytes for closing backet and curly bracket */;

		/* Add values */
		for (;;) {
			len = ( dv ? (size_t)snprintf(p, freespace, "\"%s\"", dv->name) :  vp_prints_value_json(p, freespace, vp) );
			if (len > freespace) goto no_space;
			p += len;
			freespace -= len;

			if ((next = fr_cursor_next(&cursor)) == NULL || (vp->da != next->da)) break;
			vp = next;

			if (dv) dv = dict_valbyattr(vp->da->attr, vp->da->vendor, vp->data.integer);

			if (freespace < 1) goto no_space;
			*p++ = ',';
			freespace--;
			continue;

		no_space:
			/* Rewind to last succesfully encoded offset */
			p = encoded;
			freespace = size - (p - out);

			/* Skip possible more multi-values of this attribute and advance cursor */
			while ((next = fr_cursor_next(&cursor)) && (vp->da == next->da)) vp = next;

			truncated = 1;
			goto next_attr;
		}

		/* Attribute fully added */
		*p++ = ']'; *p++ = '}'; /* We already reserved 2 bytes earlier on */
		encoded = p;

		if (next) {
			if (freespace < 1) {
				truncated = 1;
				break;
			}
			*p++ = ',';
			freespace--;
		}
	}

	if (truncated) WARN("rlm_attr_log: output buffer too small, some attributes were left out");

	/* Handle special case where the last attribute didn't fit */
	if (p[-1] == ',') {
		p--;
		freespace++;
	}

	*p++ = '}'; /* We already reserved 1 byte earlier on */
	return size - freespace;
}

static void log_request(rlm_attr_log_t *inst, REQUEST *request)
{
	DEBUG3("rlm_attr_log: logging request");

	size_t size = inst->log_size;
	char *out = (char*) talloc_size(request, size);
	if (!out) {
		ERROR("rlm_attr_log: unable to allocate output buffer");
		return;
	}

	DEBUG3("rlm_attr_log: allocated output buffer");

	int truncated = 0, len;
	char *cur = out;
	int freespace = size;

	len = snprintf(cur, freespace + 1, "%s{", inst->prefix);
	rad_assert(len < freespace + 1);
	cur += len;
	freespace -= len + 1 /* Reserve 1 byte for closing curly bracket */;

	DEBUG3("rlm_attr_log: added prefix");

	if (!request->packet) {
		WARN("rlm_attr_log: no request packet to log");
	} else {
		/* Add request */
		len = log_attrs_json(inst, request, request->packet->vps, "request", cur, freespace);
		if (len == 0) {
			truncated = 1;
		} else {
			cur += len;
			freespace -= len;
		}
	}

	DEBUG3("rlm_attr_log: added request");

	if (!request->reply) {
		WARN("rlm_attr_log: no reply packet to log");
	} else {
		/* Add reply (and skip 1 byte for ',' on succes) */
		len = log_attrs_json(inst, request, request->reply->vps, "reply", cur + 1, freespace - 1);
		if (len == 0) {
			truncated = 1;
		} else {
			*cur++ = ',';
			freespace --;

			cur += len;
			freespace -= len;
		}
	}

	DEBUG3("rlm_attr_log: added reply");

	if (!request->state) {
		WARN("rlm_attr_log: no session-state packet to log");
	} else {
		/* Add session-state (and skip 1 byt for ',' on success) */
		len = log_attrs_json(inst, request, request->state, "session-state", cur + 1, freespace - 1);
		if (len == 0) {
			truncated = 1;
		} else {
			*cur++ = ',';
			freespace --;

			cur += len;
			freespace -= len;
		}
	}

	DEBUG3("rlm_attr_log: added session-state");

	*cur++ = '}'; /* Space already reserved earlier on */

	if (truncated)
		WARN("rlm_attr_log: unable to fit request, reply and session-state in output buffer");

	DEBUG3("rlm_attr_log: message complete");

	len = send(inst->sockfd, out, cur - out, MSG_DONTWAIT);
	if (len == -1) {
		WARN("rlm_attr_log: error sending log message: %s", fr_syserror(errno));
	} else if (len < cur - out) {
		WARN("rlm_attr_log: truncated log message");
	}

	DEBUG2("rlm_attr_log: message sent");

	talloc_free(out);

	DEBUG3("rlm_attr_log: output buffer freed");
}

static rlm_rcode_t CC_HINT(nonnull) mod_preacct(void *instance, REQUEST *request)
{
	DEBUG("rlm_attr_log: mod_preacct called");
	rlm_attr_log_t *inst = instance;
	log_request(inst, request);
	return RLM_MODULE_NOOP;
}

static rlm_rcode_t CC_HINT(nonnull) mod_accounting(void *instance, REQUEST *request)
{
	DEBUG("rlm_attr_log: mod_accounting called");
	rlm_attr_log_t *inst = instance;
	log_request(inst, request);
	return RLM_MODULE_NOOP;
}

static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, REQUEST *request)
{
	DEBUG("rlm_attr_log: mod_post_auth called");
	rlm_attr_log_t *inst = instance;
	log_request(inst, request);
	return RLM_MODULE_NOOP;
}

static int mod_detach(void *instance)
{
	DEBUG3("rlm_attr_log: Detaching");

	rlm_attr_log_t *inst = instance;
	if (inst->ht) {
		fr_hash_table_free(inst->ht);
		inst->ht = NULL;
	}
	if (inst->sockfd >= 0) {
		close(inst->sockfd);
		inst->sockfd = -1;
	}

	DEBUG2("rlm_attr_log: Detached");
	return 0;
}

extern module_t rlm_attr_log;
module_t rlm_attr_log = {
	.magic = RLM_MODULE_INIT,
	.name = "attr_log",
	.type = RLM_TYPE_THREAD_SAFE,
	.inst_size = sizeof(rlm_attr_log_t),
	.config = module_config,
	.instantiate = mod_instantiate,
	.detach = mod_detach,
	.methods = {
		[MOD_PREACCT] = mod_preacct,
		[MOD_ACCOUNTING] = mod_accounting,
		[MOD_POST_AUTH] = mod_post_auth
	}
};
