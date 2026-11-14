// autoshield shadow program template.
//
// This file is emitted for review. The prototype generator also writes a tiny
// eBPF-like bytecode file that the runtime VM executes directly.

#define SHADOW_PASS 0
#define SHADOW_BLOCK 1
#define SHADOW_UNKNOWN 2

static unsigned long shadow_get_arg(unsigned long index);

int shadow_main(void)
{
    /* AUTOSHIELD_RULE_BODY */
}
