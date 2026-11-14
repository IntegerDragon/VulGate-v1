int child(void)
{
    return -ENOTTY;
}

int parent(void)
{
    int err;
    mutex_lock(&m);
    if (!pf) {
        err = child();
        goto out;
    }
    err = 0;
out:
    mutex_unlock(&m);
    return err;
}

int top(void)
{
    int err = parent();
    if (err < 0)
        return err;
    return 0;
}
