extern void __CPROVER_assert(_Bool, const char *);

static _Bool busy;

void configure(_Bool value) { busy = value; }

int request(void) {
    __CPROVER_assert(!busy, "target.available");
    return 0;
}

int handle(void) { return request(); }
