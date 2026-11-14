int locked(struct req *p) __releases(p->sem)
{
    if (p->bad)
        return -EINVAL;
    touch(p);
    return 0;
}

int caller(struct req *p)
{
    int ret = locked(p);
    if (unlikely(ret < 0))
        return ret;
    return 0;
}
