void rxrpc_input_data(struct sk_buff *skb)
{
    kfree_skb(skb);
}

void rxrpc_input_call_packet(struct sk_buff *skb)
{
    rxrpc_input_data(skb);
}
