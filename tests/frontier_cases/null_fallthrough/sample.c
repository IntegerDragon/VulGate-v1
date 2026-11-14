struct exp *find(void)
{
    if (!ready())
        return NULL;
    return obj;
}

int init(void)
{
    struct exp *exp;
    spin_lock_bh(&lock);
    exp = find();
    if (exp)
        use(exp);
    spin_unlock_bh(&lock);
    return 0;
}
