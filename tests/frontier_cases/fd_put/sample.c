int child(void)
{
    return -EINVAL;
}

int parent(int fd)
{
    struct fd f = fdget(fd);
    int ret = -EBADF;
    if (f.file) {
        ret = child();
        fdput(f);
    }
    return ret;
}

int glue(void)
{
    int ret = parent(fd);
    if (ret < 0)
        return ret;
    return 0;
}
