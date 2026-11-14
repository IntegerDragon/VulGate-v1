#ifndef VULGATE_RUNTIME_EXAMPLE_H
#define VULGATE_RUNTIME_EXAMPLE_H
struct Request { int amount; unsigned capacity; };
int handle(const struct Request *request);
void mark_pending(unsigned count, unsigned *marked);
#endif
