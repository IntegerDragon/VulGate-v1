COMPAT_SYSCALL_DEFINE1(fremovexattr, int, fd)
{
    int error = -EPERM;
    return error;
}
