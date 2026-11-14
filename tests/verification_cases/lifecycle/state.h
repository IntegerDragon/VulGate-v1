#ifndef VULGATE_LIFECYCLE_STATE_H
#define VULGATE_LIFECYCLE_STATE_H
struct WorkState {
    unsigned remaining;
    unsigned budget;
};
void initialize_work(struct WorkState *state);
void process_event(struct WorkState *state);
#endif
