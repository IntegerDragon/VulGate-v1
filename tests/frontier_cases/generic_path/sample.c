ssize_t vfs_write(struct file *file, const char *buf, size_t count)
{
    if (count > file->f_size)
        return -EFAULT;
    return count;
}

long ksys_write(unsigned int fd, const char *buf, size_t count)
{
    long ret = vfs_write(file, buf, count);
    if (ret < 0)
        return ret;
    return ret;
}
