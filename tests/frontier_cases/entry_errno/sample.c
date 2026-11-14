int pedit_act(struct sk_buff *skb)
{
    if (skb->len > 100)
        return -EINVAL;
    write_shared(skb);
    return 0;
}

int tcf_action_exec(struct sk_buff *skb)
{
    int ret = pedit_act(skb);
    if (ret < 0) {
        kfree_skb(skb);
        return ret;
    }
    return 0;
}
