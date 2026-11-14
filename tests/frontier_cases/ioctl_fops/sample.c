static int inner(struct file *file, unsigned int cmd, unsigned long arg)
{
    return -ENOTTY;
}

static long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int err;
    mutex_lock(&m);
    if (!file->private_data) {
        err = inner(file, cmd, arg);
        goto out;
    }
    err = 0;
out:
    mutex_unlock(&m);
    return err;
}

static const struct file_operations fops = {
    .unlocked_ioctl = dev_ioctl,
};
