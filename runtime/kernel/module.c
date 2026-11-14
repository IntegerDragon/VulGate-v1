#include "../autoshield.h"

#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

/*
 * The generic block stub is valid for functions whose ABI returns an integer
 * or pointer-sized value. Targets with void or aggregate returns need a typed
 * adapter rather than this generic action.
 */
static char target_symbol[KSYM_NAME_LEN];
static long configured_block_return = SHADOW_BLOCK_RETURN;
static unsigned long configured_step_limit = SHADOW_DEFAULT_STEP_LIMIT;
static bool configured_unknown_block = true;

module_param_string(target, target_symbol, KSYM_NAME_LEN, 0444);
MODULE_PARM_DESC(target, "Kernel function symbol to guard");
module_param_named(block_return, configured_block_return, long, 0444);
MODULE_PARM_DESC(block_return, "Integer/pointer return value used when a call is blocked");
module_param_named(step_limit, configured_step_limit, ulong, 0444);
MODULE_PARM_DESC(step_limit, "Maximum shadow VM instructions per invocation");
module_param_named(unknown_block, configured_unknown_block, bool, 0444);
MODULE_PARM_DESC(unknown_block, "Block UNKNOWN decisions when true");

struct autoshield_rule {
	shadow_program program;
	size_t byte_size;
	ebpf_insn insns[];
};

static DEFINE_MUTEX(rule_lock);
static struct autoshield_rule *active_rule;
static struct kprobe guard_probe;
static bool probe_registered;
static atomic64_t invocation_count = ATOMIC64_INIT(0);
static atomic64_t blocked_count = ATOMIC64_INIT(0);
static atomic64_t unknown_count = ATOMIC64_INIT(0);
static atomic64_t error_count = ATOMIC64_INIT(0);

static noinline notrace long autoshield_block_stub(void)
{
	return READ_ONCE(configured_block_return);
}
NOKPROBE_SYMBOL(autoshield_block_stub);

static bool autoshield_should_block(shadow_decision decision)
{
	switch (decision) {
	case SHADOW_BLOCK:
		return true;
	case SHADOW_UNKNOWN:
		atomic64_inc(&unknown_count);
		return READ_ONCE(configured_unknown_block);
	case SHADOW_VM_ERROR:
		atomic64_inc(&error_count);
		return true;
	case SHADOW_PASS:
	default:
		return false;
	}
}

static int autoshield_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
	struct autoshield_rule *rule = READ_ONCE(active_rule);
	shadow_policy policy;
	shadow_stats stats;
	shadow_ctx ctx;
	shadow_decision decision;
	unsigned int index;

	(void)probe;
	if (!rule)
		return 0;

	shadow_ctx_init(&ctx);
	for (index = 0; index < SHADOW_MAX_ARGS; index++) {
		ctx.args[index] = regs_get_kernel_argument(regs, index);
		ctx.regs[index] = ctx.args[index];
	}

	shadow_policy_init(&policy);
	policy.step_limit = READ_ONCE(configured_step_limit);
	policy.unknown_mode = READ_ONCE(configured_unknown_block) ?
		SHADOW_UNKNOWN_BLOCK : SHADOW_UNKNOWN_PASS;
	policy.block_return = READ_ONCE(configured_block_return);

	decision = run_ebpf_vm(&ctx, &rule->program, &policy, &stats);
	atomic64_inc(&invocation_count);
	if (!autoshield_should_block(decision))
		return 0;

	atomic64_inc(&blocked_count);
	pr_info_ratelimited("autoshield: target=%s decision=%s insns=%llu reads=%llu\n",
			    target_symbol,
			    shadow_decision_name(decision),
			    stats.instructions,
			    stats.safe_reads);

	/* Returning non-zero tells kprobes to resume at the replacement IP. */
	instruction_pointer_set(regs, (unsigned long)autoshield_block_stub);
	return 1;
}
NOKPROBE_SYMBOL(autoshield_pre_handler);

static int install_guard(struct autoshield_rule *rule)
{
	int rc;

	memset(&guard_probe, 0, sizeof(guard_probe));
	guard_probe.symbol_name = target_symbol;
	guard_probe.pre_handler = autoshield_pre_handler;

	WRITE_ONCE(active_rule, rule);
	rc = register_kprobe(&guard_probe);
	if (rc != 0) {
		WRITE_ONCE(active_rule, NULL);
		return rc;
	}

	probe_registered = true;
	pr_info("autoshield: guarding %s with %zu shadow instructions\n",
		target_symbol, rule->program.len);
	return 0;
}

static ssize_t autoshield_write(struct file *file,
				const char __user *buffer,
				size_t count,
				loff_t *position)
{
	struct autoshield_rule *rule;
	size_t instruction_count;
	int rc;

	(void)file;
	(void)position;
	if (count == 0 || count % sizeof(ebpf_insn) != 0)
		return -EINVAL;

	instruction_count = count / sizeof(ebpf_insn);
	if (instruction_count > SHADOW_MAX_PROGRAM_INSNS)
		return -E2BIG;

	mutex_lock(&rule_lock);
	if (active_rule || probe_registered) {
		rc = -EBUSY;
		goto unlock;
	}

	rule = kzalloc(struct_size(rule, insns, instruction_count), GFP_KERNEL);
	if (!rule) {
		rc = -ENOMEM;
		goto unlock;
	}

	if (copy_from_user(rule->insns, buffer, count) != 0) {
		rc = -EFAULT;
		goto free_rule;
	}

	rule->byte_size = count;
	rc = shadow_program_init(rule->insns, count, &rule->program);
	if (rc == 0)
		rc = shadow_program_validate(&rule->program);
	if (rc != 0)
		goto free_rule;

	rc = install_guard(rule);
	if (rc != 0)
		goto free_rule;

	mutex_unlock(&rule_lock);
	return count;

free_rule:
	kfree(rule);
unlock:
	mutex_unlock(&rule_lock);
	return rc;
}

static ssize_t autoshield_read(struct file *file,
			       char __user *buffer,
			       size_t count,
			       loff_t *position)
{
	char status[320];
	int length;

	(void)file;
	length = scnprintf(status, sizeof(status),
		"target=%s loaded=%u invocations=%lld blocked=%lld unknown=%lld errors=%lld\n",
		target_symbol,
		READ_ONCE(active_rule) != NULL,
		atomic64_read(&invocation_count),
		atomic64_read(&blocked_count),
		atomic64_read(&unknown_count),
		atomic64_read(&error_count));
	return simple_read_from_buffer(buffer, count, position, status, length);
}

static const struct file_operations autoshield_fops = {
	.owner = THIS_MODULE,
	.read = autoshield_read,
	.write = autoshield_write,
	.llseek = no_llseek,
};

static struct miscdevice autoshield_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "autoshield",
	.fops = &autoshield_fops,
	.mode = 0600,
};

static int __init autoshield_init(void)
{
	int rc;

	if (target_symbol[0] == '\0') {
		pr_err("autoshield: target=<kernel symbol> is required\n");
		return -EINVAL;
	}
	if (configured_step_limit == 0 ||
	    configured_step_limit > SHADOW_MAX_PROGRAM_INSNS) {
		pr_err("autoshield: step_limit must be between 1 and %u\n",
		       SHADOW_MAX_PROGRAM_INSNS);
		return -EINVAL;
	}

	rc = misc_register(&autoshield_device);
	if (rc != 0)
		return rc;

	pr_info("autoshield: ready target=%s; write verified bytecode to /dev/autoshield\n",
		target_symbol);
	return 0;
}

static void __exit autoshield_exit(void)
{
	struct autoshield_rule *rule;

	mutex_lock(&rule_lock);
	if (probe_registered) {
		unregister_kprobe(&guard_probe);
		probe_registered = false;
	}
	rule = READ_ONCE(active_rule);
	WRITE_ONCE(active_rule, NULL);
	mutex_unlock(&rule_lock);

	misc_deregister(&autoshield_device);
	kfree(rule);
	pr_info("autoshield: unloaded\n");
}

module_init(autoshield_init);
module_exit(autoshield_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("AutoShield");
MODULE_DESCRIPTION("Read-only shadow VM guard for rapid kernel vulnerability mitigation");
