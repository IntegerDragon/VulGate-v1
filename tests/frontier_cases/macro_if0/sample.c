int child(char *p)
{
#if 0
    return -EINVAL;
#else
    return -EPERM;
#endif
}

int caller(char *p)
{
    int ret = child(p);
    if (ret < 0)
        return ret;
    return 0;
}
