/* Reuse one source variable across assignment and branch-join updates. */
extern _Bool nondet_bool(void);

int main(void)
{
    unsigned char data[8] = {0};
    unsigned char *pointer = data + 1;
    __CPROVER_assert(
        __CPROVER_POINTER_OFFSET(pointer) == 1, "initial offset");

    pointer = data + 4;
    __CPROVER_assert(
        __CPROVER_POINTER_OFFSET(pointer) == 4, "offset after assignment");

    _Bool choose_first = nondet_bool();
    if (choose_first)
        pointer = data + 2;
    else
        pointer = data + 5;
    __CPROVER_assert(
        __CPROVER_POINTER_OFFSET(pointer) == (choose_first ? 2 : 5),
        "offset after branch join");

    pointer = data + 6;
    __CPROVER_assert(
        __CPROVER_POINTER_OFFSET(pointer) == 6,
        "uniform offset after mixed state");
    return 0;
}
