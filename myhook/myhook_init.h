#ifndef __MYHOOK_INIT_H__

#include <linux/debugfs.h>

typedef struct my_hook_info_t
{
	struct dentry *dbg_root;
} my_hook_info_t;

void my_hook_nf_hook_init(my_hook_info_t *hi);

#endif