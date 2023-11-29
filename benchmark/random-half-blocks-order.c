#include <time.h>
#include <stdlib.h>

int main() {
    void *addr[1000] = {0};

    for (size_t i = 0; i < 500; ++i) {
        int r = rand() % 1000;
        addr[r] = malloc(0x100000);
    }
    
    srand(time(NULL));
    for (size_t i = 0; i < 1000000; ++i) {
        int r = rand() % 1000;
        if (addr[r]) {
            free(addr[r]);
            addr[r] = NULL;
        } else {
            addr[r] = malloc(0x100000);
        }
    }
}
