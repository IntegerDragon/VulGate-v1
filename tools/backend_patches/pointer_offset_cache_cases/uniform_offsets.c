/* Two candidate objects with the same offset; no application-specific rules. */
extern _Bool nondet_bool(void);

int main(void)
{
    unsigned char first[8] = {0};
    unsigned char second[8] = {0};
    unsigned char *pointer = nondet_bool() ? first + 2 : second + 2;

    __CPROVER_assert(
        __CPROVER_POINTER_OFFSET(pointer) == 2,
        "uniform offset across objects");
    __CPROVER_assert(
        (unsigned char)__CPROVER_POINTER_OFFSET(pointer) == 2 &&
        (unsigned long)__CPROVER_POINTER_OFFSET(pointer) == 2,
        "uniform offset survives distinct result casts");
    *pointer = 17;
    __CPROVER_assert(*pointer == 17, "selected byte remains writable");
    return 0;
}
