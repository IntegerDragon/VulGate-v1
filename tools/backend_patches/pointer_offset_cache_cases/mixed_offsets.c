/* Keep a deliberate assertion counterexample to detect over-simplification. */
extern _Bool nondet_bool(void);

int main(void)
{
    unsigned char first[8] = {0};
    unsigned char second[8] = {0};
    _Bool choose_first = nondet_bool();
    unsigned char *pointer = choose_first ? first + 1 : second + 3;

    __CPROVER_assert(
        __CPROVER_POINTER_OFFSET(pointer) == (choose_first ? 1 : 3),
        "mixed offsets follow selection");
    __CPROVER_assert(
        __CPROVER_POINTER_OFFSET(pointer) == 1 ||
        __CPROVER_POINTER_OFFSET(pointer) == 3,
        "mixed offset alternatives remain represented");
    __CPROVER_assert(
        __CPROVER_POINTER_OFFSET(pointer) == 1,
        "mixed-offset counterexample preserved");
    return 0;
}
