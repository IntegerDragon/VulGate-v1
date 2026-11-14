BPF_CALL_1(bpf_chk, int, n)
{
    if (n)
        return -EINVAL;
    return 0;
}

int run(void)
{
    int ret = bpf_chk(1);
    if (WARN_ON(ret < 0))
        return ret;
    return 0;
}
