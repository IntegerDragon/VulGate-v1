int child(void)
{
    return -EINVAL;
}

int checked(void)
{
    int err = child();
    if (err < 0)
        return err;
    return 0;
}

int kernel_wrap(void)
{
    return child();
}
