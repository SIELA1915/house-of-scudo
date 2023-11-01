#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char target[256];

int main() {

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    char* firstChunk = malloc(8);
    printf("address: %p\n", firstChunk);
    printf("header: 0x%lx\n", ((unsigned long*)firstChunk)[-2]);
    char* secondChunk = malloc(8);
    printf("vulnerable chunk: %p\n", secondChunk);

    // Make sure it doesn't directly crash when freeing fake secondary
    char* secondaryChunk = malloc(1000000);

    gets(firstChunk);

    free(secondChunk);

    char* thirdChunk = malloc(150);
    printf("address: %p\n", thirdChunk);

    char* fourthChunk = malloc(0x2ff00);
    printf("secondary address: %p\n", fourthChunk);

    // Don't exit
    while (1) {
        continue;
    }
}
