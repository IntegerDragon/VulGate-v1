void child_write(char *buf, int n)
{
    memcpy(buf, src, n);
}

int parent_handle(struct req *r)
{
    char *buf = kmalloc(64, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;
    child_write(buf, r->n);
    kfree(buf);
    return 0;
}

int ioctl_entry(struct req *r)
{
    int ret = parent_handle(r);
    if (ret < 0)
        return ret;
    return 0;
}
