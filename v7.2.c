/* Derived from Linux 7.2.9 XanMod commit bca689d38274338b44a54e3bb198547c8eab8fc0. */
#include <net/netfilter/nf_conntrack_helper.h>

static void ndpi_destroy_gre_conntrack(struct nf_conn *ct)
{
#ifdef CONFIG_NF_CT_PROTO_GRE
	struct nf_conn *master = ct->master;
	struct nf_conn_help *help;

	if (!master)
		return;

	help = nfct_help(master);
	if (help) {
		struct nf_conntrack_helper *helper;

		rcu_read_lock();
		helper = rcu_dereference(help->helper);
		/* Only pptp helper has a destroy callback. */
		if (helper && helper->destroy)
			nf_ct_gre_keymap_destroy(master);

		rcu_read_unlock();
	}
#endif
}

void ndpi_nf_ct_destroy(struct nf_conntrack *nfct)
{
	struct nf_conn *ct = (struct nf_conn *)nfct;

	WARN_ON(refcount_read(&nfct->use) != 0);

	rcu_read_lock();
	ndpi_conntrack_destroy_ptr notify = rcu_dereference(nf_conntrack_destroy_cb);
	if (notify)
		notify(nfct);
	rcu_read_unlock();

	if (unlikely(nf_ct_is_template(ct))) {
		nf_ct_tmpl_free(ct);
		return;
	}

	if (unlikely(nf_ct_protonum(ct) == IPPROTO_GRE))
		ndpi_destroy_gre_conntrack(ct);

	/* Expectations will have been removed in clean_from_lists,
	 * except TFTP can create an expectation on the first packet,
	 * before connection is in the list, so we need to clean here,
	 * too.
	 */
	nf_ct_remove_expectations(ct);

	if (ct->master)
		nf_ct_put(ct->master);

	nf_conntrack_free(ct);
}
