#include <stdint.h>
uint64_t callee(uint64_t rcx);
uint64_t caller(void) {
    uint64_t rax;
    uint64_t rcx;
    rcx = (uint32_t)5;
    callee();
    rax = (uint32_t)((uint64_t)(uint32_t)rax + 1);
    return rax;
}

uint64_t callee(uint64_t rcx) {
    uint64_t rax;
    rax = (uint32_t)(uint64_t)(uint32_t)rcx;
    return rax;
}


