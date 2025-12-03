#ifndef __MY_HOOK_EXT_H__

#include <linux/skbuff.h>
#include <linux/netfilter.h>

typedef void (*my_hook_nf_hook_nf_hook_slow_t)(struct sk_buff *skb, struct nf_hook_state *state,
		const struct nf_hook_entries *e, unsigned int s, unsigned int verdict);

extern u32 my_hook_nf_hook_nf_hook_slow_enable;
extern my_hook_nf_hook_nf_hook_slow_t my_hook_nf_hook_nf_hook_slow;

#endif