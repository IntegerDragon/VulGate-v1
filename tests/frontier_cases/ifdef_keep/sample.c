#ifdef CONFIG_ON
static int helper(void)
{
    int node = target();
    if (node == SENTINEL)
        return node;
    return 0;
}
#else
static int helper(void)
{
    return 0;
}
#endif

static int target(void)
{
    return SENTINEL;
}
