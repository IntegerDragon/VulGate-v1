extern void configure(_Bool);
extern int handle(void);

int main(void) {
    configure(0);
    if (handle() != 0) return 1;
    configure(1);
    if (handle() != -1) return 2;
    configure(0);
    if (handle() != 0) return 3;
    return 0;
}
