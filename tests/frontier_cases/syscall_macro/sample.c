SYSCALL_DEFINE2(fremovexattr, int, fd, const char *, name)
{
    struct fd f = fdget(fd);
    int error = -EBADF;
    if (!fd_file(f))
        return error;
    error = strncpy_from_user(kname, name, sizeof(kname));
    if (error == 0)
        error = -ERANGE;
    if (error < 0)
        return error;
    fdput(f);
    return error;
}
