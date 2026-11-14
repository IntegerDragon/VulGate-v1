struct qops {
    int (*init)(void);
    int (*enqueue)(void);
};

int hq_init(void)
{
    if (!opt)
        return -EINVAL;
    return 0;
}

int hq_enqueue(void)
{
    classify();
    return 0;
}

static const struct qops hq = {
    .init = hq_init,
    .enqueue = hq_enqueue,
};

struct Qdisc *create(struct qops *ops)
{
    int err = ops->init();
    if (err != 0)
        return NULL;
    return sch;
}
