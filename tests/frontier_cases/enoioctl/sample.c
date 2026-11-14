struct proto_ops {
    int (*ioctl)(void);
};

int hci_ioctl(void)
{
    if (!known)
        return -ENOIOCTLCMD;
    if (!capable)
        return -EPERM;
    return 0;
}

static const struct proto_ops hci_ops = {
    .ioctl = hci_ioctl,
};

int sock_do_ioctl(struct proto_ops *ops)
{
    int err = ops->ioctl();
    if (err != -ENOIOCTLCMD)
        return err;
    return dev_ioctl();
}
