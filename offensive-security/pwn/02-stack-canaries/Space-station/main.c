#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void win() {
    printf("Mission accomplished! Opening airlock:\n");
    system("/bin/sh");
}

void vuln() {
    char buf[64];
    
    printf("Enter your astronaut ID: ");
    read(0, buf, 63);
    buf[63] = '\0';
    printf(buf);
    
    printf("\nSubmit your mission log: ");
    read(0, buf, 256);
}

int main() { 
    setup();
    printf("Welcome aboard the Space Station!\n");
    vuln();
    return 0;
}
// Arch:       amd64-64-little
// RELRO:      Full RELRO
// Stack:      Canary found
// NX:         NX enabled
// PIE:        PIE enabled
// SHSTK:      Enabled
// IBT:        Enabled
// Stripped:   No

// the canary is at %15$lx with value  a3b1413b75ec3300
//address of vuln 0x55555555535e 
