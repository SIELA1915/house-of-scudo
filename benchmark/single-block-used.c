#include <stdlib.h>

int main() {
    for (size_t i = 0; i < 1000000; ++i) {
        free(malloc(0x100000));
    }
}
