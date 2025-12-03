#include "linux/netfilter.h"
#include "linux/printk.h"
#include "linux/proc_fs.h"
#include "linux/socket.h"
#include <myhook/my_hook_ext.h>

#include <linux/ip.h>
#include "myhook_init.h"

u32 my_hook_nf_hook_nf_hook_slow_enable;
my_hook_nf_hook_nf_hook_slow_t my_hook_nf_hook_nf_hook_slow;

static void my_hook_nf_hook_nf_hook_slow_fn(struct sk_buff *skb, struct nf_hook_state *state,
		const struct nf_hook_entries *e, unsigned int s, unsigned int verdict)
{
	struct nf_hook_ops **ops;
	ops = nf_hook_entries_get_hook_ops(e);
	pr_debug("NF-CORE: pf = %s, hook = %s, elem->pri = %d verdict = %s skb %px\n",
		state->pf ==  AF_INET ? "AF_INET" :
		state->pf == AF_INET6 ? "AF_INET6" :
		state->pf == AF_BRIDGE ? "AF_BRIDGE" : "Unknown",
		state->hook == NF_INET_PRE_ROUTING ? "NF_INET_PRE_ROUTING" :
		state->hook == NF_INET_LOCAL_IN ? "NF_INET_LOCAL_IN" :
		state->hook == NF_INET_FORWARD ? "NF_INET_FORWARD" :
		state->hook == NF_INET_LOCAL_OUT ? "NF_INET_LOCAL_OUT" :
		state->hook == NF_INET_POST_ROUTING ? "NF_INET_POST_ROUTING" : "Unknown",
		ops[s]->priority,
		(verdict & NF_VERDICT_MASK) == NF_ACCEPT ? "NF_ACCEPT" :
		(verdict & NF_VERDICT_MASK) == NF_STOLEN ? "NF_STOLEN" :
		(verdict & NF_VERDICT_MASK) == NF_QUEUE ? "NF_QUEUE" :
		(verdict & NF_VERDICT_MASK) == NF_REPEAT ? "NF_REPEAT" :
		(verdict & NF_VERDICT_MASK) == NF_STOP ? "NF_STOP" : "DROP",
		skb);
	
	pr_debug("\tindev = %s, outdev : %s\n",
				state->in ? state->in->name : "NULL",
				state->out ? state->out->name : "NULL");

	if (skb->protocol == htons(ETH_P_IP))
		pr_debug("\t%pI4 -> %pI4 protocol %d id %d\n",
					&(ip_hdr(skb)->saddr), &(ip_hdr(skb)->daddr), ip_hdr(skb)->protocol, ip_hdr(skb)->id);

	return ;
}

void my_hook_nf_hook_init(my_hook_info_t *hi)
{
	debugfs_create_u32("debug_flags", 0644, hi->dbg_root, &my_hook_nf_hook_nf_hook_slow_enable);
	my_hook_nf_hook_nf_hook_slow = my_hook_nf_hook_nf_hook_slow_fn;
	return ;
}