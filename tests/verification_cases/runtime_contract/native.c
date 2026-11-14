#include "program.h"
#include <limits.h>

int main(void) {
    struct Request request = {-7, 4};
    if (handle(0) != -1 || handle(&request) != -2) return 1;
    request.amount = 4;
    if (handle(&request) != 4) return 2;
    request.amount = 5;
    if (handle(&request) != -2) return 3;
    request.amount = INT_MAX;
    request.capacity = UINT_MAX;
    if (handle(&request) != INT_MAX) return 4;
    unsigned marked = 0;
    mark_pending(UINT_MAX, &marked);
    if (marked != 0) return 5;
    mark_pending(4, &marked);
    if (marked != 1) return 6;
    return 0;
}
