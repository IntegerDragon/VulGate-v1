int child(void)
{
    if (bad())
        return -EROFS;
    return 0;
}

int parent(void)
{
    int err = 0;
    while (!err) {
        err = child();
        drop();
    }
    return err;
}
