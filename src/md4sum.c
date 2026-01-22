#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md4.h"

static void print_hex(const unsigned char *d, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        printf("%02x", d[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    MD4_CTX ctx;
    unsigned char out[16];

    if (argc > 1)
    {
        const char *s = argv[1];
        MD4_Init(&ctx);
        MD4_Update(&ctx, s, strlen(s));
        MD4_Final(out, &ctx);
        print_hex(out, 16);
        return 0;
    }

    /* read stdin */
    MD4_Init(&ctx);
    unsigned char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), stdin)) > 0)
    {
        MD4_Update(&ctx, buf, n);
    }
    MD4_Final(out, &ctx);
    print_hex(out, 16);
    return 0;
}
