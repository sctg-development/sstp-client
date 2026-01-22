/* md4.c - RFC1320 style MD4 implementation (public domain)
 * Rewritten to follow reference Decode/Encode pattern
 */

#include "md4.h"
#include <string.h>

/* Constants for MD4Transform routine. */
#define S11 3
#define S12 7
#define S13 11
#define S14 19
#define S21 3
#define S22 5
#define S23 9
#define S24 13
#define S31 3
#define S32 9
#define S33 11
#define S34 15

static void Encode(unsigned char *output, const uint32_t *input, unsigned int len)
{
    unsigned int i, j;
    for (i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = (unsigned char)(input[i] & 0xff);
        output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
        output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
        output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
    }
}

static void Decode(uint32_t *output, const unsigned char *input, unsigned int len)
{
    unsigned int i, j;
    for (i = 0, j = 0; j < len; i++, j += 4) {
        output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j+1]) << 8) |
                    (((uint32_t)input[j+2]) << 16) | (((uint32_t)input[j+3]) << 24);
    }
}

/* F, G and H are basic MD4 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* Round 1 */
#define FF(a, b, c, d, x, s) { (a) += F((b),(c),(d)) + (x); (a) = ROTATE_LEFT((a),(s)); }
/* Round 2 */
#define GG(a, b, c, d, x, s) { (a) += G((b),(c),(d)) + (x) + 0x5a827999UL; (a) = ROTATE_LEFT((a),(s)); }
/* Round 3 */
#define HH(a, b, c, d, x, s) { (a) += H((b),(c),(d)) + (x) + 0x6ed9eba1UL; (a) = ROTATE_LEFT((a),(s)); }

static void MD4Transform(uint32_t state[4], const unsigned char block[64])
{
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t x[16];

    Decode(x, block, 64);

    /* Round 1 */
    FF(a, b, c, d, x[ 0], S11);
    FF(d, a, b, c, x[ 1], S12);
    FF(c, d, a, b, x[ 2], S13);
    FF(b, c, d, a, x[ 3], S14);
    FF(a, b, c, d, x[ 4], S11);
    FF(d, a, b, c, x[ 5], S12);
    FF(c, d, a, b, x[ 6], S13);
    FF(b, c, d, a, x[ 7], S14);
    FF(a, b, c, d, x[ 8], S11);
    FF(d, a, b, c, x[ 9], S12);
    FF(c, d, a, b, x[10], S13);
    FF(b, c, d, a, x[11], S14);
    FF(a, b, c, d, x[12], S11);
    FF(d, a, b, c, x[13], S12);
    FF(c, d, a, b, x[14], S13);
    FF(b, c, d, a, x[15], S14);

    /* Round 2 */
    GG(a, b, c, d, x[ 0], S21);
    GG(d, a, b, c, x[ 4], S22);
    GG(c, d, a, b, x[ 8], S23);
    GG(b, c, d, a, x[12], S24);
    GG(a, b, c, d, x[ 1], S21);
    GG(d, a, b, c, x[ 5], S22);
    GG(c, d, a, b, x[ 9], S23);
    GG(b, c, d, a, x[13], S24);
    GG(a, b, c, d, x[ 2], S21);
    GG(d, a, b, c, x[ 6], S22);
    GG(c, d, a, b, x[10], S23);
    GG(b, c, d, a, x[14], S24);
    GG(a, b, c, d, x[ 3], S21);
    GG(d, a, b, c, x[ 7], S22);
    GG(c, d, a, b, x[11], S23);
    GG(b, c, d, a, x[15], S24);

    /* Round 3 */
    HH(a, b, c, d, x[ 0], S31);
    HH(d, a, b, c, x[ 8], S32);
    HH(c, d, a, b, x[ 4], S33);
    HH(b, c, d, a, x[12], S34);
    HH(a, b, c, d, x[ 2], S31);
    HH(d, a, b, c, x[10], S32);
    HH(c, d, a, b, x[ 6], S33);
    HH(b, c, d, a, x[14], S34);
    HH(a, b, c, d, x[ 1], S31);
    HH(d, a, b, c, x[ 9], S32);
    HH(c, d, a, b, x[ 5], S33);
    HH(b, c, d, a, x[13], S34);
    HH(a, b, c, d, x[ 3], S31);
    HH(d, a, b, c, x[11], S32);
    HH(c, d, a, b, x[ 7], S33);
    HH(b, c, d, a, x[15], S34);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    memset(x, 0, sizeof(x));
}

void MD4_Init(MD4_CTX *c)
{
    c->A = 0x67452301UL;
    c->B = 0xefcdab89UL;
    c->C = 0x98badcfeUL;
    c->D = 0x10325476UL;
    c->Nl = c->Nh = 0;
    c->num = 0;
    memset(c->data, 0, sizeof(c->data));
}

void MD4_Update(MD4_CTX *c, const void *data, size_t len)
{
    const unsigned char *input = (const unsigned char *)data;
    unsigned int index, partlen;
    unsigned int i;

    index = (unsigned int)((c->Nl >> 3) & 0x3F);

    /* Update number of bits */
    uint32_t bits = (uint32_t)(len << 3);
    c->Nl += bits;
    if (c->Nl < bits) c->Nh++;
    c->Nh += (uint32_t)(len >> 29);

    partlen = 64 - index;

    if (len >= partlen) {
        memcpy(&c->data[index], input, partlen);
        {
            uint32_t st[4] = { c->A, c->B, c->C, c->D };
            MD4Transform(st, c->data);
            c->A = st[0]; c->B = st[1]; c->C = st[2]; c->D = st[3];
        }
        for (i = partlen; i + 63 < len; i += 64) {
            uint32_t st[4] = { c->A, c->B, c->C, c->D };
            MD4Transform(st, input + i);
            c->A = st[0]; c->B = st[1]; c->C = st[2]; c->D = st[3];
        }
        index = 0;
        memcpy(&c->data[0], input + i, len - i);
        c->num = (unsigned int)(len - i);
    } else {
        memcpy(&c->data[index], input, len);
        c->num = index + (unsigned int)len;
    }
}

void MD4_Final(unsigned char *md, MD4_CTX *c)
{
    unsigned char bits[8];
    unsigned int index, padlen;
    uint32_t state[4];

    state[0] = c->A; state[1] = c->B; state[2] = c->C; state[3] = c->D;

    bits[0] = (unsigned char)(c->Nl & 0xff);
    bits[1] = (unsigned char)((c->Nl >> 8) & 0xff);
    bits[2] = (unsigned char)((c->Nl >> 16) & 0xff);
    bits[3] = (unsigned char)((c->Nl >> 24) & 0xff);
    bits[4] = (unsigned char)(c->Nh & 0xff);
    bits[5] = (unsigned char)((c->Nh >> 8) & 0xff);
    bits[6] = (unsigned char)((c->Nh >> 16) & 0xff);
    bits[7] = (unsigned char)((c->Nh >> 24) & 0xff);

    index = (unsigned int)((c->Nl >> 3) & 0x3f);
    padlen = (index < 56) ? (56 - index) : (120 - index);

    static unsigned char PADDING[64] = { 0x80 };

    MD4_Update(c, PADDING, padlen);
    MD4_Update(c, bits, 8);

    Encode(md, (uint32_t[]){ c->A, c->B, c->C, c->D }, 16);

    c->A = state[0]; c->B = state[1]; c->C = state[2]; c->D = state[3];

    memset(c->data, 0, sizeof(c->data));
    c->num = 0;
}
