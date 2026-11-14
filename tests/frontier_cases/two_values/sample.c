int fn(int a, int b)
{
    if (a)
        return -EPERM;
    if (b)
        return -EINVAL;
    return 0;
}

int caller(int a, int b)
{
    int ret = fn(a, b);
    if (ret < 0)
        return ret;
    return 0;
}
