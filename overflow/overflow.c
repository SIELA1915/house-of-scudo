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
    printf("header: %llu\n", *(unsigned long long*)(firstChunk - 16));
    char* secondChunk = malloc(8);

    printf("secondChunkAddress: %p\n", secondChunk);
    printf("secondChunkHeader: %llu\n", *(unsigned long long*)(secondChunk - 16));

    gets(firstChunk);

    // Don't exit
    char test;
    gets(test);
}
