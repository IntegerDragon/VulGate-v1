int child(void)
{
    if (denied())
        return -EPERM;
    return 0;
}

bool gate(void)
{
    int err;
    task_lock(task);
    err = child();
    task_unlock(task);
    return !err;
}
