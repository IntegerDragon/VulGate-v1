struct obj *make(int n)
{
    if (n)
        return ERR_PTR(-EINVAL);
    return ptr;
}

int caller(void)
{
    struct obj *obj = make(1);
    if (unlikely(IS_ERR_OR_NULL(obj)))
        return PTR_ERR(obj);
    return 0;
}
