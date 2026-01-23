/*!
 * @brief Routines for handling CHAP authentication.
 *
 * @file sstp-chap.c
 *
 * @author Copyright (C) 2026 Ronan Le Meillat - SCTG Development,
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sstp-chap.h"

int main(void)
{
    uint8_t peer[16] = {
        0x21, 0x60, 0x6e, 0x07, 0x38, 0x35, 0x6f, 0xec,
        0xc6, 0x03, 0xf5, 0xa0, 0x5d, 0x88, 0x64, 0xa1};
    uint8_t auth[16] = {
        0x88, 0x79, 0x61, 0x12, 0x34, 0x56, 0x78, 0x90,
        0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89};
    const char *user = "User";
    const char *pass = "clientPass";
    uint8_t nt1[24];
    uint8_t nt2[24];

    uint8_t phash[16];
    uint8_t challenge[8];

    int r = sstp_chap_nt_password_hash(pass, phash);
    if (r < 0)
    {
        printf("sstp_chap_nt_password_hash failed: %d\n", r);
        return EXIT_FAILURE;
    }

    r = sstp_chap_challenge_hash(peer, auth, user, challenge);
    if (r < 0)
    {
        printf("sstp_chap_challenge_hash failed: %d\n", r);
        return EXIT_FAILURE;
    }

    r = sstp_chap_generate_nt_response(challenge, phash, nt1);
    if (r < 0)
    {
        printf("sstp_chap_generate_nt_response failed: %d\n", r);
        return EXIT_FAILURE;
    }

    /* Recompute and compare for determinism */
    r = sstp_chap_generate_nt_response(challenge, phash, nt2);
    if (r < 0)
    {
        printf("sstp_chap_generate_nt_response(second) failed: %d\n", r);
        return EXIT_FAILURE;
    }

    if (memcmp(nt1, nt2, sizeof(nt1)) != 0)
    {
        printf("NT-Response is not deterministic\n");
        return EXIT_FAILURE;
    }

    /* Basic sanity check: not all zeros */
    int i, allzero = 1;
    for (i = 0; i < 24; i++)
    {
        if (nt1[i] != 0)
        {
            allzero = 0;
            break;
        }
    }

    if (allzero)
    {
        printf("NT-Response all zeros\n");
        return EXIT_FAILURE;
    }

    printf("MS-CHAPv2 NT-Response generation OK\n");
    return EXIT_SUCCESS;
}
