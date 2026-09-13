#include <stdio.h>
#include <stdint.h>

extern uint64_t sm_checksum(const unsigned char *buffer, uint64_t length);

int main(void) {
    unsigned char buffer[4096];
    size_t length = fread(buffer, 1, sizeof(buffer), stdin);
    printf("%llu\n", (unsigned long long)sm_checksum(buffer, (uint64_t)length));
    return ferror(stdin) ? 1 : 0;
}