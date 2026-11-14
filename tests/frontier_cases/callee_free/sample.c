void drop_stream(struct stream *stream)
{
    kfree(stream->formats);
    kfree(stream);
}

int parse(void)
{
    if (short_buf())
        return -EINVAL;
    return 12;
}

int streaming(void)
{
    void *format = kzalloc(32, GFP_KERNEL);
    if (!format)
        return -ENOMEM;
    int ret = parse();
    if (ret < 0)
        goto error;
    return 0;
error:
    drop_stream(stream);
    return ret;
}

int glue(void)
{
    int ret = streaming();
    if (ret < 0)
        return ret;
    return 0;
}
