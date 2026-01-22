/* md4.h - RFC1320 compatible MD4 implementation
 * Public domain implementation
 */

#ifndef __MD4_H__
#define __MD4_H__

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct
    {
        uint32_t A, B, C, D; /* state */
        uint32_t Nl, Nh;     /* number of bits, low and high */
        unsigned char data[64];
        unsigned int num; /* number of bytes in data */
    } MD4_CTX;

    void MD4_Init(MD4_CTX *c);
    void MD4_Update(MD4_CTX *c, const void *data, size_t len);
    void MD4_Final(unsigned char *md, MD4_CTX *c);

#ifdef __cplusplus
}
#endif

#endif /* __MD4_H__ */
