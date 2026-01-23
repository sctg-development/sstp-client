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
#include <stdint.h>
#include <unistd.h>
#include "sstp-private.h"
#include "sstp-state.h"
#include "sstp-client.h"
#include "sstp-chap.h"

/* Capture buffer written by sstp_stream_send */
static unsigned char captured[8192];
static int captured_len = 0;

/* Stub sstp_stream_send used by sstp_state_send_ppp_frame */
status_t sstp_stream_send(sstp_stream_st *stream, sstp_buff_st *buf, sstp_complete_fn cb, void *arg, int timeout)
{
    if (!buf || buf->len <= 0)
        return SSTP_FAIL;

    if (buf->len > (int)sizeof(captured))
        return SSTP_FAIL;

    memcpy(captured, buf->data, buf->len);
    captured_len = buf->len;
    return SSTP_OKAY;
}

int main(void)
{
    uint8_t auth_challenge[16];
    for (int i = 0; i < 16; i++)
        auth_challenge[i] = (unsigned char)(0x10 + i);

    uint8_t peer_challenge[16];
#ifdef __APPLE__
    arc4random_buf(peer_challenge, sizeof(peer_challenge));
#else
    if (RAND_bytes(peer_challenge, sizeof(peer_challenge)) != 1)
    {
        printf("Could not generate peer challenge\n");
        return EXIT_FAILURE;
    }
#endif

    uint8_t nt_response[24];
    if (sstp_chap_mschapv2_nt_response(peer_challenge, auth_challenge, "testuser", "password123", nt_response) < 0)
    {
        printf("Failed to compute nt_response\n");
        return EXIT_FAILURE;
    }

    /* Construct CHAP response value: peer(16) + nt_response(24) + flags(1) */
    unsigned char value[16 + 24 + 1];
    memcpy(value, peer_challenge, 16);
    memcpy(value + 16, nt_response, 24);
    value[16 + 24] = 0x00;

    /* Now use sstp_chap_mppe_get() to compute MPPE keys given the nt_response */
    sstp_chap_st ctx;
    memset(&ctx, 0, sizeof(ctx));
    memcpy(ctx.nt_response, nt_response, 24);
    memcpy(ctx.challenge, auth_challenge, 16);

    uint8_t skey[16], rkey[16];
    if (sstp_chap_mppe_get(&ctx, "password123", skey, rkey, 0) != 0)
    {
        printf("Could not compute MPPE keys\n");
        return EXIT_FAILURE;
    }

    int any = 0;
    for (int i = 0; i < 16; i++)
    {
        if (skey[i] != 0 || rkey[i] != 0)
        {
            any = 1;
            break;
        }
    }

    if (!any)
    {
        printf("MPPE keys are all zero\n");
        return EXIT_FAILURE;
    }

    printf("CHAP flow unit test OK\n");
    return EXIT_SUCCESS;
}
