int target(void)
{
    if (!ready())
        return SENTINEL;
    return 0;
}

int helper(void)
{
    int node = target();
    if (node >= SENTINEL)
        return node;
    return -EAGAIN;
}
