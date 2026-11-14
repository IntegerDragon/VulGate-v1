struct proto_ops {
    int (*connect)(void);
};

struct socket {
    struct proto_ops *ops;
};

int sco_sock_connect(void)
{
    if (!open)
        return -EBADFD;
    return 0;
}

static const struct proto_ops sco_sock_ops = {
    .connect = sco_sock_connect,
};

int __sys_connect_file(struct socket *sock)
{
    return READ_ONCE(sock->ops)->connect();
}

int connect(void)
{
    return __sys_connect_file(sock);
}

int caller(void)
{
    int ret = connect();
    if (ret < 0)
        return ret;
    return 0;
}
