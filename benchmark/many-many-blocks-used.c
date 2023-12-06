#include <stdlib.h>

int main() {
    void *addr[10000];
    for (size_t j = 0; j < 100; ++j) {
        for (size_t i = 0; i < 10000; ++i) {
            addr[i] = malloc(0x100000);
        }
        for (size_t i = 0; i < 10000; ++i) {
            free(addr[i]);
        }
    }
}
