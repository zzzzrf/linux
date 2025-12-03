#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>

#include "myhook_init.h"

MODULE_DESCRIPTION("My kernel module");
MODULE_AUTHOR("Me");
MODULE_LICENSE("GPL");

static int msg_level = -1;
module_param(msg_level, int, 0);
MODULE_PARM_DESC(msg_level, "Override default message level");

static char *msg_text = "default message";
module_param(msg_text, charp, 0444);
MODULE_PARM_DESC(msg_text, "Override default message text");

static my_hook_info_t my_hook_info;

static void my_hook_debugfs_init(my_hook_info_t *hi)
{
	hi->dbg_root = debugfs_create_dir("my_hook", NULL);
}

static int __init my_hook_init(void)
{
	pr_emerg("Hi\n");
	pr_emerg("msg_level : %d\n", msg_level);
	pr_emerg("msg_text : %s\n", msg_text);

	my_hook_debugfs_init(&my_hook_info);

#ifdef CONFIG_MY_HOOK_NF_DEBUG
	my_hook_nf_hook_init(&my_hook_info);
#endif
	return 0;
}

static void my_hook_exit(void)
{
	pr_emerg("Bye\n");
	return;
}

module_init(my_hook_init);
module_exit(my_hook_exit);