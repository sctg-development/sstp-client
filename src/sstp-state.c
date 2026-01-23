/*!
 * @brief State machine for SSTP layer
 *
 * @file sstp-state.h
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
#include "sstp-private.h"
#include "sstp-chap.h"
#include "sstp-client.h"
#include <openssl/rand.h>

/*!
 * @brief The context structure for the SSTP state machine
 */
struct sstp_state
{
    /*! The state of the machine */
    int state;

    /*! Specifies the server or client mode */
    int mode;

    /*! The current client connection */
    sstp_stream_st *stream;

    /*! The tx-buffer */
    sstp_buff_st *tx_buf;

    /*! The rx-buffer */
    sstp_buff_st *rx_buf;

    void *fwctx;

    sstp_state_forward_fn forward_cb;

    /*! The state transition function */
    sstp_state_change_fn state_cb;

    /*! The user context argument to state_cb */
    void *uarg;

    /*! The certificate hash protocol */
    int proto;

    /*! The disconnect status */
    int status;

    /*! The echo request counter */
    int echo;

    /*! The binding request value */
    uint8_t nounce[32];

    /*! The MPPE send key for HLAK */
    uint8_t mppe_send_key[16];

    /*! The MPEE receive key for HLAK */
    uint8_t mppe_recv_key[16];

    /*! Stored CHAP context (used when no pppd/plugin is running) */
    sstp_chap_st chap; // holds challenge/nt_response etc, filled when we handle CHAP inline

};

void sstp_state_set_forward(sstp_state_st *state, sstp_state_forward_fn forward, void *arg)
{
    state->forward_cb = forward;
    state->fwctx = arg;
}

/*!
 * @par Make this generic
 */
static void sstp_state_send_complete(sstp_stream_st *stream,
                                     sstp_buff_st *buf, sstp_state_st *ctx, status_t status)
{
    if (SSTP_OKAY != status)
    {
        ctx->state_cb(ctx->uarg, SSTP_CALL_ABORT);
        return;
    }

    // Depends on the state .. but we might need to read here.

    return;
}

/*
 * Helper: send a PPP frame (raw payload) over the SSTP data channel
 */
static status_t sstp_state_send_ppp_frame(sstp_state_st *ctx, const unsigned char *payload, int plen)
{
    status_t status = SSTP_FAIL;
    int flen = (plen << 1) + 4;
    unsigned char *enc = NULL;
    int ret = 0;

    enc = alloca(flen);
    if (!enc)
        goto done;

    ret = sstp_frame_encode(payload, plen, enc, &flen);
    if (SSTP_OKAY != ret)
    {
        log_err("Could not encode PPP frame");
        goto done;
    }

    /* Create SSTP data packet and append encoded frame */
    ret = sstp_pkt_init(ctx->tx_buf, SSTP_MSG_DATA);
    if (SSTP_OKAY != ret)
        goto done;

    if ((ctx->tx_buf->len + flen) > ctx->tx_buf->max)
    {
        log_err("TX buffer too small for PPP frame");
        goto done;
    }

    memcpy(&ctx->tx_buf->data[ctx->tx_buf->len], enc, flen);
    ctx->tx_buf->len += flen;
    sstp_pkt_update(ctx->tx_buf);

    status = sstp_stream_send(ctx->stream, ctx->tx_buf, (sstp_complete_fn)sstp_state_send_complete, ctx, 1);

done:
    return status;
}

/*
 * Helper: handle PPP frames, intercept MS-CHAPv2 challenge/response
 * Returns 1 if handled (no further forwarding), 0 otherwise.
 */
static int sstp_state_handle_ppp_frame(sstp_state_st *state, unsigned char *frame, int flen)
{
    uint16_t proto = (frame[0] & 0x10) ? frame[0] : (frame[0] << 8 | frame[1]);
    const unsigned char *pkt = frame;
    int plen = flen;

    /* Not an auth CHAP packet? ignore */
    if (proto != SSTP_PPP_AUTH_CHAP)
        return 0;

    /* CHAP code at pkt[2], id at pkt[3], value-size at pkt[6], value starts at pkt[7] */
    unsigned char code = pkt[2];
    unsigned char id = pkt[3];

    /* We only handle MS-CHAPv2 when running as client without pppd/plugin */
    if (state->mode != SSTP_MODE_CLIENT)
        return 0;

    sstp_client_st *client = (sstp_client_st *)state->uarg;
    if (!client || !client->option.user || !client->option.password)
        return 0;

    if (code == 0x01)
    {
        /* CHAP Challenge: build an MS-CHAPv2 response */
        size_t vlen = pkt[6] & 0xFF;
        if (vlen < 16 || (7 + (int)vlen) > plen)
            return 0;

        uint8_t auth_challenge[16];
        memcpy(auth_challenge, &pkt[7], 16);

        /* Generate PeerChallenge */
        uint8_t peer_challenge[16];
#ifdef __APPLE__
        arc4random_buf(peer_challenge, sizeof(peer_challenge));
#else
        if (RAND_bytes(peer_challenge, sizeof(peer_challenge)) != 1)
        {
            log_err("Could not generate peer challenge");
            return 0;
        }
#endif

        /* Compute NT-Response */
        uint8_t nt_response[24];
        if (sstp_chap_mschapv2_nt_response(peer_challenge, auth_challenge, client->option.user, client->option.password, nt_response) < 0)
        {
            log_err("Failed to compute MS-CHAPv2 NT-Response");
            return 0;
        }

        /* Build CHAP Response packet: proto(2) + Code(1=2) + ID + Len(2) + ValSize(1) + Peer(16)+NT(24)+Flag(1)+Name */
        int name_len = (int)strlen(client->option.user);
        int val_size = 16 + 24 + 1;
        int chap_len = 4 + 1 + val_size + name_len;
        int total_plen = 2 + chap_len; /* include proto */
        unsigned char *out = malloc(total_plen);
        if (!out)
            return 0;

        /* Protocol */
        out[0] = (unsigned char)((SSTP_PPP_AUTH_CHAP >> 8) & 0xFF);
        out[1] = (unsigned char)(SSTP_PPP_AUTH_CHAP & 0xFF);

        out[2] = 0x02; /* Response */
        out[3] = id;   /* same id as challenge */
        out[4] = (unsigned char)((chap_len >> 8) & 0xFF);
        out[5] = (unsigned char)(chap_len & 0xFF);
        out[6] = (unsigned char)val_size;

        /* Value: PeerChallenge */
        memcpy(&out[7], peer_challenge, 16);
        /* NT-Response */
        memcpy(&out[7 + 16], nt_response, 24);
        /* Flags */
        out[7 + 16 + 24] = 0x00;
        /* Username */
        memcpy(&out[7 + 16 + 24 + 1], client->option.user, name_len);

        /* Store the computed NT-Response into our state chap context so that when server sends Success we can obtain MPPE keys */
        memset(&state->chap, 0, sizeof(state->chap));
        memcpy(state->chap.nt_response, nt_response, sizeof(state->chap.nt_response));
        memcpy(state->chap.challenge, auth_challenge, sizeof(state->chap.challenge));

        /* Send frame */
        sstp_state_send_ppp_frame(state, out, total_plen);
        free(out);

        return 1;
    }
    else if (code == 0x03)
    {
        /* CHAP Success: compute MPPE keys and accept the state */
        uint8_t skey[16], rkey[16];
        if (sstp_chap_mppe_get(&state->chap, ((sstp_client_st *)state->uarg)->option.password, skey, rkey, 0) == 0)
        {
            sstp_state_mppe_keys(state, skey, sizeof(skey), rkey, sizeof(rkey));
            /* Now we are authenticated, move to connected state */
            sstp_state_accept(state);
        }

        return 1;
    }

    return 0;
}

/*
 * Exported helper: set the CHAP context in state (used by other code paths)
 */
void sstp_state_chap_challenge(sstp_state_st *ctx, sstp_chap_st *chap)
{
    if (!ctx || !chap)
        return;

    memcpy(&ctx->chap, chap, sizeof(ctx->chap));
}

#ifdef __SSTP_UNIT_TEST_MSCHAP_FLOW
int sstp_state_get_nt_response(sstp_state_st *state, unsigned char out[24])
{
    if (!state || !out)
        return -1;
    memcpy(out, state->chap.nt_response, 24);
    return 0;
}

int sstp_state_mppe_keys_set(sstp_state_st *state)
{
    if (!state)
        return 0;
    for (int i = 0; i < 16; i++)
    {
        if (state->mppe_send_key[i] != 0 || state->mppe_recv_key[i] != 0)
            return 1;
    }
    return 0;
}
#endif
/*!
 * @brief Handle the SSTP control message: CALL_CONNECT_ACK
 */
static void sstp_state_connect_ack(sstp_state_st *ctx, sstp_msg_t type,
                                   sstp_buff_st *buf)
{
    sstp_attr_st *attrs[SSTP_ATTR_MAX + 1];
    sstp_attr_st *attr = NULL;
    status_t status = SSTP_FAIL;
    int count = SSTP_ATTR_MAX + 1;
    int ret = 0;
    int len = 0;
    int index = 0;
    char *data = NULL;

    /* Obtain the attributes */
    ret = sstp_pkt_parse(buf, count, attrs);
    if (SSTP_OKAY != ret)
    {
        log_err("Could not parse attributes");
        goto done;
    }

    /* Get the crypto attribute */
    attr = attrs[SSTP_ATTR_CRYPTO_BIND_REQ];
    if (attr == NULL)
    {
        log_err("Could not get bind request attribute");
        goto done;
    }

    /* Get pointer and length */
    data = sstp_attr_data(attr);
    len = sstp_attr_len(attr);

    /* Check the buffer */
    if (!data || len != 36)
    {
        log_err("Invalid Crypto Binding Request");
        goto done;
    }

    /* Get the cerficate protocol support */
    ctx->proto = data[index + 3] & 0xFF;
    index += 4;

    /* Copy the binding request */
    memset(ctx->nounce, 0, sizeof(ctx->nounce));
    memcpy(ctx->nounce, &data[index], len - index);

    /* Lets handle the PPP negotiation */
    ctx->state_cb(ctx->uarg, SSTP_CALL_CONNECT);
    return;

done:

    if (SSTP_OKAY != status)
    {
        ctx->state_cb(ctx->uarg, SSTP_CALL_ABORT);
    }
}

/*!
 * @brief Send a Echo-Request to when timed out.
 */
static status_t sstp_state_echo_request(sstp_state_st *ctx)
{
    status_t status = SSTP_FAIL;

    log_info("Sending Echo-Request Message");

    /* Create the echo reply */
    status = sstp_pkt_init(ctx->tx_buf, SSTP_ECHO_REQUEST);
    if (SSTP_OKAY != status)
    {
        goto done;
    }

    /* Dump the packet */
    sstp_pkt_trace(ctx->tx_buf);

    /* Send the Echo Response back to server */
    status = sstp_stream_send(ctx->stream, ctx->tx_buf, (sstp_complete_fn)sstp_state_send_complete, ctx, 10);

    /* Increment the retry counter */
    ctx->echo++;

done:

    return status;
}

/*!
 * @brief Send a Echo Reply message in response to an Echo Request
 */
static status_t sstp_state_echo_reply(sstp_state_st *ctx)
{
    status_t status = SSTP_FAIL;

    log_info("Sending Echo-Reply Message");

    /* Create the echo reply */
    status = sstp_pkt_init(ctx->tx_buf, SSTP_ECHO_REPLY);
    if (SSTP_OKAY != status)
    {
        goto done;
    }

    /* Dump the packet */
    sstp_pkt_trace(ctx->tx_buf);

    /* Send the Echo Response back to server */
    status = sstp_stream_send(ctx->stream, ctx->tx_buf, (sstp_complete_fn)sstp_state_send_complete, ctx, 10);

done:

    return status;
}

/*!
 * @brief Send a disconnect message
 */
static status_t sstp_state_disconnect(sstp_state_st *ctx)
{
    status_t status = SSTP_FAIL;

    log_info("Sending Disconnect Message");

    /* Create the echo reply */
    status = sstp_pkt_init(ctx->tx_buf, SSTP_MSG_DISCONNECT);
    if (SSTP_OKAY != status)
    {
        goto done;
    }

    /* Dump the packet */
    sstp_pkt_trace(ctx->tx_buf);

    /* Send the Echo Response back to server */
    status = sstp_stream_send(ctx->stream, ctx->tx_buf, (sstp_complete_fn)sstp_state_send_complete, ctx, 10);

done:

    return status;
}

/*!
 * @brief Send a Disconnect ACK message to peer
 */
static status_t sstp_state_disconnect_ack(sstp_state_st *ctx)
{
    status_t status = SSTP_FAIL;

    log_info("Sending Disconnect Ack Message");

    /* Create the echo reply */
    status = sstp_pkt_init(ctx->tx_buf, SSTP_MSG_DISCONNECT_ACK);
    if (SSTP_OKAY != status)
    {
        goto done;
    }

    /* Dump the packet */
    sstp_pkt_trace(ctx->tx_buf);

    /* Send the Echo Response back to server */
    status = sstp_stream_send(ctx->stream, ctx->tx_buf, (sstp_complete_fn)sstp_state_send_complete, ctx, 10);

done:

    return status;
}

/*!
 * @brief Handle a Connect NAK message
 */
static status_t sstp_state_connect_nak(sstp_state_st *ctx, sstp_msg_t type,
                                       sstp_buff_st *buf)
{
    sstp_attr_st *attrs[SSTP_ATTR_MAX + 1];
    sstp_attr_st *attr = NULL;
    status_t retval = SSTP_FAIL;
    uint32_t status = 0;
    // uint8_t id = 0;
    int count = SSTP_ATTR_MAX + 1;
    int ret = 0;
    int len = 0;
    int index = 0;
    char *data = NULL;

    /* Obtain the attributes */
    ret = sstp_pkt_parse(buf, count, attrs);
    if (SSTP_OKAY != ret)
    {
        log_err("Could not parse attributes");
        goto done;
    }

    /* Get the status info attribute */
    attr = attrs[SSTP_ATTR_STATUS_INFO];
    if (!attr)
    {
        log_err("Could not get status info attribute");
        goto done;
    }

    /* Get the data pointers */
    data = sstp_attr_data(attr);
    len = sstp_attr_len(attr);
    if (len < 4)
    {
        log_err("Invalid status attribute");
        goto done;
    }

    /* Get the faulty attribute */
    // id = data[index+3] & 0xFF;
    index += 4;

    /* Get the status */
    memcpy(&status, &data[index], sizeof(status));
    ctx->status = ntohl(status);
    index += sizeof(status);

    // TODO: DUMP ATTRIBUTE BUFFER HERE

    /* Success! */
    retval = SSTP_OKAY;

done:

    return retval;
}

/*!
 * @brief Handle control packets as they arrive
 */
static void sstp_state_handle_ctrl(sstp_state_st *state, sstp_buff_st *buf,
                                   sstp_msg_t type)
{
    status_t ret = SSTP_FAIL;

    // log_info("Handle Control Message: %d", type);
    switch (type)
    {
    case SSTP_MSG_CONNECT_ACK:
        sstp_state_connect_ack(state, type, buf);
        break;

    case SSTP_MSG_CONNECT_NAK:
        log_info("Connect NAK Message");
        ret = sstp_state_connect_nak(state, type, buf);
        if (SSTP_OKAY == ret)
        {
            sstp_state_disconnect(state);
        }
        break;

    case SSTP_MSG_ABORT:
        ret = sstp_state_connect_nak(state, type, buf);
        if (SSTP_OKAY == ret)
        {
            state->state_cb(state->uarg, SSTP_CALL_ABORT);
        }
        break;

    case SSTP_MSG_DISCONNECT:
        ret = sstp_state_connect_nak(state, type, buf);
        if (SSTP_OKAY == ret)
        {
            sstp_state_disconnect_ack(state);
        }
        state->state_cb(state->uarg, SSTP_CALL_DISCONNECT);
        break;

    case SSTP_MSG_DISCONNECT_ACK:
        state->state_cb(state->uarg, SSTP_CALL_DISCONNECT);
        break;

    case SSTP_ECHO_REQUEST:
        sstp_state_echo_reply(state);
        break;

    case SSTP_ECHO_REPLY:
        state->echo = 0;
        break;

    default:
        log_err("Unhandled Error message: %d", type);
        break;
    }
}

/*!
 * @brief Handle data packets
 */
static status_t sstp_state_handle_data(sstp_state_st *state,
                                       sstp_buff_st *buf)
{
    status_t ret = SSTP_FAIL;

    /* If no forward function is set, handle PPP frames inline (e.g., MS-CHAPv2 when --nolaunchpppd) */
    if (!state->forward_cb)
    {
        unsigned char *p = (unsigned char *)sstp_pkt_data(buf);
        int plen = sstp_pkt_data_len(buf);
        int off = 0;

        while (off < plen)
        {
            int inlen = plen - off;
            int outmax = 16384;
            unsigned char outbuf[16384];
            int ret2 = sstp_frame_decode(p + off, &inlen, outbuf, &outmax);

            if (ret2 == SSTP_OVERFLOW || (inlen == 0))
            {
                /* Need more data or overflow, stop processing */
                break;
            }

            if (ret2 != SSTP_OKAY)
            {
                /* Could not decode frame; advance and continue */
                off += inlen;
                continue;
            }

            /* outbuf now contains a single PPP frame payload of length outmax */
            if (sstp_state_handle_ppp_frame(state, outbuf, outmax))
            {
                /* Frame handled by internal CHAP logic; continue to next */
                off += inlen;
                continue;
            }

            /* Not handled; we could forward to outside if needed */
            off += inlen;
        }

        /* No forward set; we handled what we could */
        return SSTP_OKAY;
    }

    /* Forward the data back to the pppd layer */
    ret = state->forward_cb(state->fwctx, sstp_pkt_data(buf),
                            sstp_pkt_data_len(buf));
    if (SSTP_OKAY != ret)
    {
        log_err("Could not forward packet to pppd");
    }

    return ret;
}

/*!
 * @brief Handle the sstp packet received
 */
static void sstp_state_handle_packet(sstp_state_st *ctx, sstp_buff_st *buf)
{
    sstp_msg_t type;

    /* Dump Packet */
    sstp_pkt_trace(buf);

    /* Handle the packet type */
    switch (sstp_pkt_type(buf, &type))
    {
    case SSTP_PKT_DATA:
        sstp_state_handle_data(ctx, buf);
        break;

    case SSTP_PKT_CTRL:
        sstp_state_handle_ctrl(ctx, buf, type);
        break;

    case SSTP_PKT_UNKNOWN:
        log_err("Unrecognized SSTP message");
        break;
    }
}

/*!
 * @brief Called from sstp_client_recv_sstp() when a complete sstp packet
 *  has been received.
 */
static void sstp_state_recv(sstp_stream_st *stream, sstp_buff_st *buf,
                            sstp_state_st *ctx, status_t status)
{
    switch (status)
    {
    case SSTP_TIMEOUT:

        /* If we have seen no traffic, then disconnect */
        if (ctx->echo > 4)
        {
            ctx->state_cb(ctx->uarg, SSTP_CALL_ABORT);
            return;
        }

        /* Send a echo request */
        sstp_state_echo_request(ctx);
        break;

    case SSTP_OKAY:
        sstp_state_handle_packet(ctx, buf);
        break;

    case SSTP_FAIL:
    default:
        /* Map stream status errors to a state machine abort event */
        ctx->state_cb(ctx->uarg, SSTP_CALL_ABORT);
        return;
    }

    /* Setup a receiver for SSTP messages */
    sstp_stream_setrecv(ctx->stream, sstp_stream_recv_sstp, ctx->rx_buf,
                        (sstp_complete_fn)sstp_state_recv, ctx, 60);
}

/*!
 * @brief Send the connect request to the server
 */
static status_t sstp_state_send_request(sstp_state_st *ctx)
{
    status_t status = SSTP_FAIL;
    uint16_t proto = htons(SSTP_ENCAP_PROTO_PPP);
    int ret;

    log_info("Sending Connect-Request Message");

    /* Initialize the pointer using */
    ret = sstp_pkt_init(ctx->tx_buf, SSTP_MSG_CONNECT_REQ);
    if (SSTP_OKAY != ret)
    {
        goto done;
    }

    /* Append an attribute */
    ret = sstp_pkt_attr(ctx->tx_buf, SSTP_ATTR_ENCAP_PROTO,
                        sizeof(proto), &proto);
    if (SSTP_OKAY != ret)
    {
        goto done;
    }

    /* Dump the packet */
    sstp_pkt_trace(ctx->tx_buf);

    /* Send the Call Connect request to the server */
    status = sstp_stream_send(ctx->stream, ctx->tx_buf, (sstp_complete_fn)sstp_state_send_complete, ctx, 10);
    if (SSTP_OKAY == status)
    {
        /* Setup a receiver for SSTP messages */
        sstp_stream_setrecv(ctx->stream, sstp_stream_recv_sstp, ctx->rx_buf,
                            (sstp_complete_fn)sstp_state_recv, ctx, 60);
    }

done:

    if (SSTP_OKAY != status)
    {
        ctx->state_cb(ctx->uarg, SSTP_CALL_ABORT);
    }

    return status;
}

/*!
 * @brief Send the Connected message to the server
 */
static status_t sstp_state_send_connect(sstp_state_st *ctx)
{
    status_t status = SSTP_FAIL;
    status_t ret = SSTP_FAIL;
    int pos = 0;
    int len = 32;
    uint8_t type = 0;
    uint8_t data[100];
    cmac_ctx_st cmac;

    log_info("Sending Connected Message");

    /* Reset the memory */
    memset(data, 0, sizeof(data));

    /* Get the protocol type supported by this message */
    type = (ctx->proto & SSTP_PROTO_HASH_SHA256)
               ? SSTP_PROTO_HASH_SHA256
               : SSTP_PROTO_HASH_SHA1;

    /* Certificate Hash Protocol */
    data[3] = type;
    pos += 4;

    /* The server generated random (nounce) */
    memcpy(&data[pos], ctx->nounce, sizeof(ctx->nounce));
    pos += sizeof(ctx->nounce);

    /* The server certificate hash */
    ret = sstp_get_cert_hash(ctx->stream, ctx->proto,
                             &data[pos], len);
    if (SSTP_OKAY != ret)
    {
        goto done;
    }

    /* Create the message */
    ret = sstp_pkt_init(ctx->tx_buf, SSTP_MSG_CONNECTED);
    if (SSTP_OKAY != ret)
    {
        goto done;
    }

    /* Add the attribute */
    ret = sstp_pkt_attr(ctx->tx_buf, SSTP_ATTR_CRYPTO_BIND,
                        sizeof(data), data);
    if (SSTP_OKAY != ret)
    {
        goto done;
    }

    /* Get the CMAC Field */
    sstp_cmac_init(&cmac, (int)type);
    sstp_cmac_send_key(&cmac, ctx->mppe_send_key,
                       sizeof(ctx->mppe_send_key));
    sstp_cmac_recv_key(&cmac, ctx->mppe_recv_key,
                       sizeof(ctx->mppe_recv_key));
    sstp_cmac_result(&cmac, (uint8_t *)&ctx->tx_buf->data[0],
                     ctx->tx_buf->len, (uint8_t *)&ctx->tx_buf->data[80], 32);

    /* Dump the packet */
    sstp_pkt_trace(ctx->tx_buf);

    /* Success */
    status = sstp_stream_send(ctx->stream, ctx->tx_buf, (sstp_complete_fn)sstp_state_send_complete, ctx, 10);
    if (SSTP_OKAY == status)
    {
        ctx->state_cb(ctx->uarg, SSTP_CALL_ESTABLISHED);
    }

    /* Set the established flag */
    ctx->state |= SSTP_ST_ESTABLISHED;

done:

    /* In case of failure */
    if (SSTP_OKAY != status)
    {
        ctx->state_cb(ctx->uarg, SSTP_CALL_ABORT);
    }

    return status;
}

status_t sstp_state_start(sstp_state_st *state)
{
    int retval = SSTP_FAIL;

    switch (state->mode)
    {
    case SSTP_MODE_CLIENT:

        /* Send the connect request to the server */
        retval = sstp_state_send_request(state);
        break;

    case SSTP_MODE_SERVER:
    default:
        retval = SSTP_NOTIMPL;
        break;
    }

    return (retval);
}

status_t sstp_state_accept(sstp_state_st *ctx)
{
    status_t ret = SSTP_FAIL;

    switch (ctx->mode)
    {
    case SSTP_MODE_CLIENT:
        /* Send the connect ACK to server */
        ret = sstp_state_send_connect(ctx);
        break;

    case SSTP_MODE_SERVER:
    default:
        ret = SSTP_NOTIMPL;
        break;
    }

    return ret;
}

status_t sstp_state_mppe_keys(sstp_state_st *ctx, unsigned char *skey,
                              size_t slen, unsigned char *rkey, size_t rlen)
{
    status_t status = SSTP_FAIL;

    /* Check the length */
    if ((slen != sizeof(ctx->mppe_send_key)) ||
        (rlen != sizeof(ctx->mppe_recv_key)))
    {
        goto done;
    }

    /* Copy the MPPE keys */
    memcpy(ctx->mppe_send_key, skey, sizeof(ctx->mppe_send_key));
    memcpy(ctx->mppe_recv_key, rkey, sizeof(ctx->mppe_recv_key));

    /* Success */
    status = SSTP_OKAY;

done:

    return status;
}

const char *sstp_state_reason(sstp_state_st *ctx)
{
    return (ctx->state != 0)
               ? sstp_attr_status_str(ctx->status)
               : "Reason was not known";
}

void sstp_state_free(sstp_state_st *state)
{
    if (!state)
    {
        return;
    }

    /* Free the receive buffer */
    if (state->rx_buf)
    {
        sstp_buff_destroy(state->rx_buf);
        state->rx_buf = NULL;
    }

    /* Free the transmit buffer */
    if (state->tx_buf)
    {
        sstp_buff_destroy(state->tx_buf);
        state->tx_buf = NULL;
    }

    /* Free the state object */
    free(state);
}

status_t sstp_state_create(sstp_state_st **state, sstp_stream_st *stream,
                           sstp_state_change_fn state_cb, void *ctx, int mode)
{
    int status = 0;
    int ret = 0;

    /* Allocate memory for the state object */
    *state = calloc(1, sizeof(sstp_state_st));
    if (!*state)
    {
        goto done;
    }

    /* Initialize the State context */
    (*state)->uarg = ctx;
    (*state)->state_cb = state_cb;
    (*state)->mode = mode;
    (*state)->stream = stream;

    /* Allocate send buffer */
    ret = sstp_buff_create(&(*state)->tx_buf, 16384);
    if (SSTP_OKAY != ret)
    {
        goto done;
    }

    /* Allocate receive buffer */
    ret = sstp_buff_create(&(*state)->rx_buf, 16384);
    if (SSTP_OKAY != ret)
    {
        goto done;
    }

    /* Success */
    status = SSTP_OKAY;

done:

    if (SSTP_OKAY != status)
    {
        sstp_state_free(*state);
        *state = NULL;
    }

    return status;
}
