#include "linux/netfilter/nf_conntrack_tuple_common.h"
#include "linux/printk.h"
#include "myhook_init.h"

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_l4proto.h>

static const char* l4proto_name(u16 proto)
{
	switch (proto) {
	case IPPROTO_ICMP: return "icmp";
	case IPPROTO_TCP: return "tcp";
	case IPPROTO_UDP: return "udp";
	case IPPROTO_DCCP: return "dccp";
	case IPPROTO_GRE: return "gre";
	case IPPROTO_SCTP: return "sctp";
	case IPPROTO_UDPLITE: return "udplite";
	case IPPROTO_ICMPV6: return "icmpv6";
	}

	return "unknown";
}

static const char* ctinfo_name(enum ip_conntrack_info ctinfo)
{
	switch (ctinfo) {
	case IP_CT_ESTABLISHED: return "ESTABLISHED";
	case IP_CT_RELATED: return "RELATED";
	case IP_CT_NEW: return "NEW";
	case IP_CT_IS_REPLY: return "REPLY";
	// case IP_CT_ESTABLISHED_REPLY: return "ESTAB+REPLY";
	case IP_CT_RELATED_REPLY: return "RELATED+REPLY";
	case IP_CT_NUMBER: return "NUMBER";
	case IP_CT_UNTRACKED: return "UNTRACKED";
	}

	return "unknown";
}

static unsigned int nf_ct_show(void *priv,
                              struct sk_buff *skb,
                              const struct nf_hook_state *state)
{
	struct nf_conn *ct;
	struct nf_conntrack_tuple *orig, *repl;
	const struct nf_conntrack_l4proto *l4proto;
	enum ip_conntrack_info ctinfo;

	ct = nf_ct_get(skb, &ctinfo);
	if (ct == 0)
	{
		pr_debug("[%s][%d] ct is null\n", __func__, __LINE__);
		return NF_ACCEPT;
	}

	orig = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	if (orig->src.l3num != NFPROTO_IPV4)
		return NF_ACCEPT;

	repl = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;
	l4proto = nf_ct_l4proto_find(nf_ct_protonum(ct));

	pr_debug("ctinfo:%s L3:%s[%d],L4:%s:[%d] dir:%d,src=%pI4,dst=%pI4 dir:%d,src=%pI4,dst=%pI4",
			ctinfo_name(ctinfo), "ipv4", nf_ct_l3num(ct),
			l4proto ? l4proto_name(l4proto->l4proto) : "null",
			nf_ct_protonum(ct),
			IP_CT_DIR_ORIGINAL, &orig->src.u3.ip, &orig->dst.u3.ip,
			IP_CT_DIR_REPLY, &repl->src.u3.ip, &repl->dst.u3.ip);

    return NF_ACCEPT;
}

static const struct nf_hook_ops nf_ct_show_ops[] = {
{
		.hook = nf_ct_show,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK - 1,
	},
	{
		.hook = nf_ct_show,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 1,
	},
	{
		.hook = nf_ct_show,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_CONNTRACK - 1,
	},
	{
		.hook = nf_ct_show,
		.pf = PF_INET,
		.hooknum = 	NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_NAT_SRC - 1,
	},
	{
		.hook = nf_ct_show,
		.pf = PF_INET,
		.hooknum = 	NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_NAT_SRC - 1,
	},
	{
		.hook = nf_ct_show,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_NAT_SRC - 1,
	},
	{
		.hook = nf_ct_show,
		.pf = PF_INET,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK_CONFIRM - 1,
	},
	{
		.hook = nf_ct_show,
		.pf = PF_INET,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_CONNTRACK_CONFIRM - 1,
	},
};

int my_nf_ct_init(my_hook_info_t *hi)
{
	int err = 0;
	err = nf_register_net_hooks(&init_net, nf_ct_show_ops, ARRAY_SIZE(nf_ct_show_ops));
	if (err)
		pr_emerg("[%s][%d] nf_register_net_hooks failed\n", __func__, __LINE__);
	return err;
}