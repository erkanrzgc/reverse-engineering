#include <stdint.h>
#include <stdio.h>
#include <windows.h>
uint64_t flags_gap(uint64_t rcx) {
    uint64_t rax;
    /* 0x1000: cmp ecx,0 */
    /* 0x1003: nop */
    if (/* condition: 0x1004 je short 000000000000100Ch */ 1) {
        rax = (uint32_t)0;
        return rax;
    } else {
        rax = (uint32_t)1;
        return rax;
    }
}
uint64_t looping(uint64_t rcx) {
    uint64_t rax;
    rax = (uint32_t)0;
    rax = (uint32_t)((uint64_t)(uint32_t)rax + 1);
    rcx = (uint32_t)((uint64_t)(uint32_t)rcx - 1);
    /* 0x1009: jne short 0000000000001005h */
    rax = (uint32_t)(uint64_t)(uint32_t)rax;
    return rax;
}
uint64_t memory_partial(void) {
    uint64_t local_8;
    uint64_t rax;
    local_8 = (uint32_t)287454020;
    local_8 = (uint8_t)85;
    rax = (uint32_t)(uint64_t)(uint32_t)local_8;
    return rax;
}
static void *native(const unsigned char *bytes, size_t size) { void *p=VirtualAlloc(NULL,size,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE); memcpy(p,bytes,size); return p; }
int main(void) {
 unsigned char flags[] = {0x83,0xf9,0,0x90,0x74,6,0xb8,1,0,0,0,0xc3,0x31,0xc0,0xc3};
 unsigned char loop[] = {0xb8,0,0,0,0,0xff,0xc0,0xff,0xc9,0x75,0xfa,0x89,0xc0,0xc3};
 unsigned char mem[] = {0x55,0x48,0x89,0xe5,0x48,0x83,0xec,0x10,0xc7,0x45,0xf8,0x44,0x33,0x22,0x11,0xc6,0x45,0xf8,0x55,0x8b,0x45,0xf8,0xc9,0xc3};
 uint64_t (*f)(uint64_t)=native(flags,sizeof flags); uint64_t (*l)(uint64_t)=native(loop,sizeof loop); uint64_t (*m)(void)=native(mem,sizeof mem);
 printf("flags_gap(1): emitted=%llu native=%llu\n",(unsigned long long)flags_gap(1),(unsigned long long)f(1));
 printf("looping(3): emitted=%llu native=%llu\n",(unsigned long long)looping(3),(unsigned long long)l(3));
 printf("memory_partial(): emitted=%llx native=%llx\n",(unsigned long long)memory_partial(),(unsigned long long)m());
 return 0;
}
