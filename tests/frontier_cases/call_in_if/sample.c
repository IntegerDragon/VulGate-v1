struct class_ops {
    int (*dump)(void);
};

int do_dump(void)
{
    walk();
    return -EMSGSIZE;
}

static const struct class_ops cops = {
    .dump = do_dump,
};

int fill(struct class_ops *cl_ops)
{
    if (cl_ops->dump && cl_ops->dump() < 0)
        return -EMSGSIZE;
    return 0;
}
