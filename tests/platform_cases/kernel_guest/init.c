#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/utsname.h>
#include <unistd.h>

int main(void)
{
    struct utsname identity;
    int console = open("/dev/console", O_RDWR);
    if (console >= 0) {
        dup2(console, 0); dup2(console, 1); dup2(console, 2);
        if (console > 2) close(console);
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    if (getpid() != 1 || uname(&identity) ||
        mount("proc", "/proc", "proc", 0, NULL) ||
        mount("sysfs", "/sys", "sysfs", 0, NULL)) {
        puts("VULGATE_GUEST_FAILED: initialization");
        goto done;
    }
    FILE *file = fopen("/proc/sys/kernel/ostype", "r");
    char value[32] = {0};
    if (!file || !fgets(value, sizeof(value), file) || strcmp(value, "Linux\n")) {
        puts("VULGATE_GUEST_FAILED: procfs");
        if (file) fclose(file);
        goto done;
    }
    fclose(file);
    printf("VULGATE_GUEST_BOOT_OK: %s %s\n", identity.release, identity.machine);
done:
    sync();
    reboot(RB_AUTOBOOT);
    for (;;) pause();
}
