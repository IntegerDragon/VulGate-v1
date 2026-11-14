struct proto_ops {
    int (*ioctl)(void);
};

struct socket {
    struct proto_ops *ops;
};

int hci_ioctl(void)
{
    if (!known)
        return -ENOIOCTLCMD;
    return -EPERM;
}

static const struct proto_ops hci_ops = {
    .ioctl = hci_ioctl,
};

int sock_do_ioctl(struct socket *sock)
{
    int err = sock->ops->ioctl();
    if (err != -ENOIOCTLCMD)
        return err;
    return dev_ioctl();
}
