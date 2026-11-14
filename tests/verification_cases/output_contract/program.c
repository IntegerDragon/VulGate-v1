extern void __CPROVER_assert(_Bool, const char *);

static int fill_value(int *out, int reject) {
    *out = 0;
    if (reject) return -1;
    __CPROVER_assert(0, "target.unavailable_operation");
    return 0;
}

void verify_request(void) {
    int value;
    int rc = fill_value(&value, 1);
    if (rc < 0) __CPROVER_assert(value == 0, "contract.output_initialized_to_zero");
}
