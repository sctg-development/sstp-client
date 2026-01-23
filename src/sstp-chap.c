/*!
 * @brief Routines for handling CHAP authentication.
 *
 * @file sstp-chap.c
 *
 * @author Copyright (C) 2011 Eivind Naess, 2026 Ronan Le Meillat - SCTG Development,
 *      All Rights Reserved
 *
 * @par License:
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <config.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/sha.h>
#include "md4.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/des.h>
#include "sstp-private.h"
#include "sstp-chap.h"

#ifdef __SSTP_UNIT_TEST_CHAP
#undef log_err
#define log_err(x, args...) \
    printf(x "\n", ##args)
#endif

/*< Indicate that we are sending */
#define SSTP_CHAP_SENDING 0x01

/*< Indicating that we are acting as a server */
#define SSTP_CHAP_SERVER 0x02

/*!
 * @brief Create the a double MD4 hash from a password made into unicode
 * @param pass  The password as specified by command line
 * @param len   The length of the password
 * @param hash  The resulting hash from this operation.
 *
 * @retval 0: success, -1: failure
 */
static int sstp_chap_hash_pass(const char *pass, int len,
                               uint8_t hash[16])
{
    uint8_t buf[512] = {};
    uint8_t inx;

    MD4_CTX ctx;

    if (len > 255)
        return -1;

    /* Convert to unicode */
    for (inx = 0; inx < len; inx++)
        buf[(inx << 1)] = pass[inx];

    /* Use local MD4 implementation (RFC1320) */
    MD4_Init(&ctx);
    MD4_Update(&ctx, buf, (size_t)(len << 1));
    MD4_Final(hash, &ctx);

    /* Double MD4 */
    MD4_Init(&ctx);
    MD4_Update(&ctx, hash, 16);
    MD4_Final(hash, &ctx);

    return 0;
}

/*!
 * @brief Create the master key given the nt_response from handshake
 *  and the double MD4 password hash
 *
 * @param phash     The double MD4 password hash
 * @param nt_resp   The nt_response field from MSCHAP handshake
 * @param master    The master key
 * @param mlen      The length of the master key
 *
 * @retval 0: success (always)
 */
static int sstp_chap_hash_master(uint8_t phash[16], uint8_t nt_resp[24],
                                 uint8_t master[16], uint8_t mlen)
{
    uint8_t buf[SHA_DIGEST_LENGTH];
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md = NULL;
    unsigned int outlen = 0;

    /* The magic constant used in key derivations for chap */
    static unsigned char magic1[27] =
        {
            0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
            0x68, 0x65, 0x20, 0x4d, 0x50, 0x50, 0x45, 0x20, 0x4d,
            0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79};

    /* Perform the SHA1 operation using EVP */
    md = EVP_sha1();
    if (md == NULL)
        return -1;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        return -1;

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    if (EVP_DigestUpdate(mdctx, phash, 16) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    if (EVP_DigestUpdate(mdctx, nt_resp, 24) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    if (EVP_DigestUpdate(mdctx, magic1, 27) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    if (EVP_DigestFinal_ex(mdctx, buf, &outlen) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    /* Copy the result to the output */
    memcpy(master, buf, mlen);
    return 0;
}

/*!
 * @brief Create the session's MPPE send / receive keys
 * @param key    The output key
 * @param master The master key
 * @param flag   Indication if we are sending, and acting as a server
 *
 * @retval 0: success, -1: failure
 */
static int sstp_chap_hash_session(uint8_t key[16], uint8_t master[16],
                                  uint8_t flag)
{
    uint8_t buf[SHA_DIGEST_LENGTH];
    uint8_t pad[40];
    uint8_t *magic;
    SHA_CTX ctx;

    /* Magic2:
     * "On the client side, this is the send key; on the server side,
     *  it is the receive key."
     */
    uint8_t magic2[84] =
        {
            0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
            0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
            0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
            0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
            0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
            0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65,
            0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
            0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
            0x6b, 0x65, 0x79, 0x2e};

    /* Magic3:
     * "On the client side, this is the receive key; on the server side,
     "  it is the send key."
     */
    uint8_t magic3[84] =
        {
            0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
            0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
            0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
            0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
            0x6b, 0x65, 0x79, 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68,
            0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73,
            0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73,
            0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20,
            0x6b, 0x65, 0x79, 0x2e};

    memset(buf, 0, 20);

    if (SSTP_CHAP_SENDING & flag)
    {
        magic = (SSTP_CHAP_SERVER & flag)
                    ? magic3
                    : magic2;
    }
    else
    {
        magic = (SSTP_CHAP_SERVER & flag)
                    ? magic2
                    : magic3;
    }

    /* Compute the session key using EVP */
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md = EVP_sha1();
    unsigned int outlen = 0;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        return -1;

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    if (EVP_DigestUpdate(mdctx, master, 16) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    /* Add the padding: 40-bytes of 0x00 */
    memset(&pad, 0x00, sizeof(pad));
    if (EVP_DigestUpdate(mdctx, pad, sizeof(pad)) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    /* Add the 84-bytes of magic */
    if (EVP_DigestUpdate(mdctx, magic, 84) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    /* Add the padding: 40-bytes of 0xf2 */
    memset(pad, 0xf2, sizeof(pad));
    if (EVP_DigestUpdate(mdctx, pad, sizeof(pad)) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    /* Get the final update */
    if (EVP_DigestFinal_ex(mdctx, buf, &outlen) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);

    /* Keep the 16 first bytes of the digest */
    memcpy(key, buf, 16);
    return 0;
}

/*
 * Compute NT Password Hash: MD4(Unicode(password))
 */
int sstp_chap_nt_password_hash(const char *pass, uint8_t hash[16])
{
    uint8_t buf[512] = {};
    int len = (int)strlen(pass);
    int inx;
    MD4_CTX ctx;

    if (len > 255)
        return -1;

    /* Convert to unicode (little endian) */
    for (inx = 0; inx < len; inx++)
    {
        buf[(inx << 1)] = (uint8_t)pass[inx];
        buf[(inx << 1) + 1] = 0x00;
    }

    /* Single MD4 */
    MD4_Init(&ctx);
    MD4_Update(&ctx, buf, (size_t)(len << 1));
    MD4_Final(hash, &ctx);

    return 0;
}

/*
 * ChallengeHash = SHA1(PeerChallenge || AuthChallenge || Username) -> first 8 bytes
 */
int sstp_chap_challenge_hash(const uint8_t peer[16], const uint8_t auth[16], const char *user, uint8_t challenge[8])
{
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md = NULL;
    unsigned int outlen = 0;
    uint8_t buf[SHA_DIGEST_LENGTH];
    size_t ulen = strlen(user);

    md = EVP_sha1();
    if (md == NULL)
        return -1;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        return -1;

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (EVP_DigestUpdate(mdctx, peer, 16) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (EVP_DigestUpdate(mdctx, auth, 16) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (ulen && EVP_DigestUpdate(mdctx, user, ulen) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (EVP_DigestFinal_ex(mdctx, buf, &outlen) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);

    memcpy(challenge, buf, 8);
    return 0;
}

/*
 * Helper: Convert 7 bytes -> 8-byte DES key with odd parity (parity bit is LSB)
 */
static void sstp_des_7_to_8(const uint8_t in[7], uint8_t out[8])
{
    out[0] = in[0] & 0xFE;
    out[1] = ((in[0] << 7) | (in[1] >> 1)) & 0xFE;
    out[2] = ((in[1] << 6) | (in[2] >> 2)) & 0xFE;
    out[3] = ((in[2] << 5) | (in[3] >> 3)) & 0xFE;
    out[4] = ((in[3] << 4) | (in[4] >> 4)) & 0xFE;
    out[5] = ((in[4] << 3) | (in[5] >> 5)) & 0xFE;
    out[6] = ((in[5] << 2) | (in[6] >> 6)) & 0xFE;
    out[7] = (in[6] << 1) & 0xFE;

    /* Set odd parity for each byte: if parity of upper 7 bits is even set LSB to 1 */
    for (int i = 0; i < 8; i++)
    {
        unsigned char b = out[i] & 0xFE; /* clear parity bit */
#ifdef __GNUC__
        int ones = __builtin_popcount((unsigned int)b);
#else
        int ones = 0;
        unsigned char tmp = b;
        while (tmp) { ones += tmp & 1; tmp >>= 1; }
#endif
        if ((ones & 1) == 0)
            out[i] |= 0x01;
        else
            out[i] &= 0xFE;
    }
} 

/*
 * Generate NT-Response from 8-byte challenge and 16-byte password hash
 */
int sstp_chap_generate_nt_response(const uint8_t challenge[8], const uint8_t password_hash[16], uint8_t nt_response[24])
{
    uint8_t zpwd[21];
    uint8_t key8[8];
    uint8_t outbuf[16];
    int i;

    memset(zpwd, 0, sizeof(zpwd));
    memcpy(zpwd, password_hash, 16);

    for (i = 0; i < 3; i++)
    {
        /* Expand 7 bytes -> 8-byte DES key with odd parity */
        sstp_des_7_to_8(zpwd + i * 7, key8);

        /* Expanded key calculated (odd-parity applied) */
        /* Note: key material is not logged to avoid leaking sensitive data */

        /* Use EVP to perform DES-ECB encryption without padding */
        const EVP_CIPHER *cipher = EVP_des_ecb();
        if (!cipher)
        {
            /* Fallback: use legacy DES API if EVP cipher isn't available */
            uint8_t dkey[8];
            uint8_t dout[8];

            sstp_des_7_to_8(zpwd + i * 7, dkey);

            log_err("EVP_des_ecb not available, using legacy DES");

            /* Use deprecated DES functions but suppress warnings around them */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
            {
                DES_cblock keyblk;
                DES_key_schedule ks;
                memcpy(&keyblk, dkey, 8);
                DES_set_key_unchecked(&keyblk, &ks);
                DES_ecb_encrypt((DES_cblock *)challenge, (DES_cblock *)dout, &ks, DES_ENCRYPT);
            }
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

            /* Legacy DES used for this block */
            log_err("Using legacy DES implementation for NT-Response computation");

            memcpy(nt_response + (i * 8), dout, 8);
            continue;
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            log_err("EVP_CIPHER_CTX_new failed");
            return -1;
        }

        if (EVP_EncryptInit_ex(ctx, cipher, NULL, key8, NULL) != 1)
        {
            unsigned long err = ERR_get_error();
            char buferr[256];
            ERR_error_string_n(err, buferr, sizeof(buferr));
            fprintf(stderr, "EVP_EncryptInit_ex failed: %s\n", buferr);

            /* Fallback to legacy DES if EVP cipher init is unsupported */
            log_err("EVP_EncryptInit_ex failed: %s; falling back to legacy DES", buferr);
            EVP_CIPHER_CTX_free(ctx);

            uint8_t dkey[8];
            uint8_t dout[8];
            sstp_des_7_to_8(zpwd + i * 7, dkey);

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
            {
                DES_cblock keyblk;
                DES_key_schedule ks;
                memcpy(&keyblk, dkey, 8);
                DES_set_key_unchecked(&keyblk, &ks);
                DES_ecb_encrypt((DES_cblock *)challenge, (DES_cblock *)dout, &ks, DES_ENCRYPT);
            }
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

            /* Legacy DES used for this block */
            log_err("Using legacy DES implementation for NT-Response computation");

            memcpy(nt_response + (i * 8), dout, 8);
            continue;
        }

        EVP_CIPHER_CTX_set_padding(ctx, 0);

        int outlen = 0;
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, (const unsigned char *)challenge, 8) != 1)
        {
            unsigned long err = ERR_get_error();
            char buferr[256];
            ERR_error_string_n(err, buferr, sizeof(buferr));
            fprintf(stderr, "EVP_EncryptUpdate failed: %s\n", buferr);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        int outlen2 = 0;
        if (EVP_EncryptFinal_ex(ctx, outbuf + outlen, &outlen2) != 1)
        {
            unsigned long err = ERR_get_error();
            char buferr[256];
            ERR_error_string_n(err, buferr, sizeof(buferr));
            fprintf(stderr, "EVP_EncryptFinal_ex failed: %s\n", buferr);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        EVP_CIPHER_CTX_free(ctx);

        if ((outlen + outlen2) != 8)
        {
            log_err("Unexpected DES output length: %d", outlen + outlen2);
            return -1;
        }

        /* EVP DES output computed successfully */

        memcpy(nt_response + (i * 8), outbuf, 8);
    }

    return 0;
}

/*
 * High-level MS-CHAPv2 NT-Response generator
 */
int sstp_chap_mschapv2_nt_response(const uint8_t peer_challenge[16], const uint8_t auth_challenge[16], const char *user, const char *password, uint8_t nt_response[24])
{
    uint8_t password_hash[16];
    uint8_t challenge[8];

    if (sstp_chap_nt_password_hash(password, password_hash) < 0)
        return -1;

    if (sstp_chap_challenge_hash(peer_challenge, auth_challenge, user, challenge) < 0)
        return -1;

    if (sstp_chap_generate_nt_response(challenge, password_hash, nt_response) < 0)
        return -1;

    return 0;
}

int sstp_chap_mppe_get(sstp_chap_st *ctx, const char *password,
                       uint8_t skey[16], uint8_t rkey[16], char server)
{
    uint8_t phash[16];  // Password Hash Hash
    uint8_t master[16]; // Master Key
    uint8_t flag = 0;
    int ret = -1;

    /* Set the flag */
    if (server)
    {
        flag |= SSTP_CHAP_SENDING;
    }

    /* Get password */
    ret = sstp_chap_hash_pass(password, strlen(password), phash);
    if (ret < 0)
    {
        log_err("Could not create password hash");
        goto done;
    }

    /* Get the master key */
    ret = sstp_chap_hash_master(phash, ctx->nt_response,
                                master, sizeof(master));
    if (ret < 0)
    {
        log_err("Could not create master key");
        goto done;
    }

    /* Get the receiving key */
    ret = sstp_chap_hash_session(rkey, master, flag);
    if (ret < 0)
    {
        log_err("Could not create receiving MPPE key");
        goto done;
    }

    /* Get the sending Key */
    flag |= SSTP_CHAP_SENDING;
    ret = sstp_chap_hash_session(skey, master, flag);
    if (ret < 0)
    {
        log_err("Could not create sending MPPE key");
        goto done;
    }

    /* Success */
    ret = 0;

done:

    return ret;
}

#ifdef __SSTP_UNIT_TEST_CHAP

#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    int retval = EXIT_FAILURE;

    sstp_chap_st ctx =
        {
            .challenge =
                {
                    0x21, 0x60, 0x6e, 0x07, 0x38, 0x35, 0x6f, 0xec,
                    0xc6, 0x03, 0xf5, 0xa0, 0x5d, 0x88, 0x64, 0xa1},
            .nt_response =
                {
                    0x85, 0x9a, 0x0c, 0x0e, 0xce, 0x47, 0x4d, 0xf2,
                    0x0d, 0x0a, 0xe8, 0x31, 0xac, 0x3a, 0xe3, 0xd2,
                    0x4f, 0x82, 0x6e, 0x93, 0x67, 0x9e, 0x36, 0xbc},
        };

    uint8_t cmp1[16] =
        {
            0x00, 0x0b, 0xc1, 0xde, 0xa2, 0xcb, 0x85, 0x16,
            0xbc, 0x77, 0xf5, 0x52, 0xb9, 0xec, 0x5a, 0x03};

    uint8_t cmp2[16] =
        {
            0x93, 0xd9, 0x27, 0x06, 0xf5, 0x13, 0xa2, 0xea,
            0x50, 0xf8, 0xcd, 0x94, 0x69, 0x57, 0x3c, 0xdb};

    uint8_t skey[16];
    uint8_t rkey[16];

    /* Get the MPPE keys */
    sstp_chap_mppe_get(&ctx, "DukeNuke3D", skey, rkey, false);

    /* Check the send key */
    if (memcmp(skey, cmp1, 16))
    {
        printf("Send key Failed!\n");
        goto done;
    }

    printf("The MPPE send key is correct\n");

    /* Check the receive key */
    if (memcmp(rkey, cmp2, 16))
    {
        printf("Receive Key Failed!\n");
        goto done;
    }

    printf("The MPPE recv key is correct\n");

    /* Success! */
    retval = EXIT_SUCCESS;

done:

    return retval;
}

#endif
