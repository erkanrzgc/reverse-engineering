/* Controlled native oracle, independent of Rust and Ghidra C generation. */
#include <stdint.h>
#include <stdio.h>
extern uint64_t fixture_conditional(uint64_t x);
extern uint64_t fixture_imul(uint64_t x);
extern uint64_t fixture_partial(void);
extern uint64_t fixture_movzx(void);
extern uint64_t fixture_indexed_lea(uint64_t base, uint64_t index);
int main(void) {
    printf("{\"conditional_zero\":%llu,\"conditional_one\":%llu,\"imul\":%llu,\"partial\":%llu,\"movzx\":%llu,\"indexed_lea\":%llu}\n",
           (unsigned long long)fixture_conditional(0),
           (unsigned long long)fixture_conditional(1),
           (unsigned long long)fixture_imul(3),
           (unsigned long long)fixture_partial(),
           (unsigned long long)fixture_movzx(),
           (unsigned long long)fixture_indexed_lea(100, 3));
    return 0;
}
