#include <stdlib.h>

int main() {
    void *addr[1000];
    for (size_t j = 0; j < 1000; ++j) {
        for (size_t i = 0; i < 1000; ++i) {
            addr[i] = malloc(0x100000);
        }
        for (size_t i = 0; i < 1000; ++i) {
            free(addr[i]);
        }
    }
}
