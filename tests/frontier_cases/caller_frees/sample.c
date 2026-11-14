int child(char *p)
{
    if (p[0] == 0)
        return -EINVAL;
    touch(p);
    return 0;
}

int parent(void)
{
    char *p = kmalloc(16, GFP_KERNEL);
    if (!p)
        return -ENOMEM;
    int ret = child(p);
    if (ret < 0) {
        kfree(p);
        return ret;
    }
    kfree(p);
    return 0;
}

int syscall_glue(void)
{
    int ret = parent();
    if (ret < 0)
        return ret;
    return 0;
}
