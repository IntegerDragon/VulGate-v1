/* Multi-process fixture: a parent forks exec'd workers that call a target. */
#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

__attribute__((noinline, visibility("default")))
int forker_target(uint64_t x, uint64_t y)
{
    return (int)((x + y) * 7);
}

static int worker(int index, int iterations)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    for (int k = 0; k < iterations; k++) {
        int result = forker_target(1, 5);
        printf("child %d pid %d iteration %d result %d\n",
               index, (int)getpid(), k, result);
        usleep(50000);
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--worker") == 0) {
        int index = argc > 2 ? atoi(argv[2]) : 0;
        int iterations = argc > 3 ? atoi(argv[3]) : 40;
        return worker(index, iterations);
    }
    int children = argc > 1 ? atoi(argv[1]) : 3;
    int iterations = argc > 2 ? atoi(argv[2]) : 40;
    if (children < 0 || children > 32 || iterations < 1 || iterations > 100000) {
        fprintf(stderr, "usage: %s [children 0..32] [iterations]\n", argv[0]);
        return 2;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    for (int i = 0; i < children; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            return 1;
        }
        if (pid == 0) {
            char index[16];
            char count[16];
            snprintf(index, sizeof(index), "%d", i);
            snprintf(count, sizeof(count), "%d", iterations);
            execl("/proc/self/exe", "forker", "--worker", index, count, (char *)NULL);
            perror("execl");
            _exit(127);
        }
    }
    for (int i = 0; i < children; i++) {
        wait(NULL);
    }
    return 0;
}
