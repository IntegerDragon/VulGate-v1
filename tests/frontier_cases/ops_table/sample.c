struct net_ops {
    int (*act)(void);
};

int do_act(void)
{
    if (bad)
        return -EPERM;
    return 0;
}

static const struct net_ops sample_ops = {
    .act = do_act,
};

int dispatch(struct net_ops *ops)
{
    int err = ops->act();
    if (err < 0)
        return err;
    return 0;
}
