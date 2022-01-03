/*
* Author: Christian Huitema
* Copyright (c) 2021, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <picoquic_internal.h>
#include <picoquic_packet_loop.h>
#include <autoqlog.h>
#include <performance_log.h>
#include "fuzi_q.h"

/* The fuzzer can be used with multiple applications, with multiple ALPN.
 * There is no application specific code in the fuzzer. 
 * For server side fuzzer, the context is set according to the ALPN 
 * presented by the client, using `picoquic_demo_server_callback` and
 * `picoquic_demo_server_callback_select_alpn`
 */

int fuzi_q_server_loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode,
    void* callback_ctx, void* callback_arg)
{
    int ret = 0;
    fuzi_q_ctx_t* cb_ctx = (fuzi_q_ctx_t*)callback_ctx;

    if (cb_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        switch (cb_mode) {
        case picoquic_packet_loop_ready:
            fprintf(stdout, "Waiting for packets.\n");
            break;
        case picoquic_packet_loop_after_receive:
            break;
        case picoquic_packet_loop_after_send:
            break;
        case picoquic_packet_loop_port_update:
            break;
        default:
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            break;
        }
    }
    return ret;
}

/* Fuzi Quic Server
 * TODO: manage loop options like key updates, migrations, etc. 
 */
int fuzi_q_server(fuzi_q_mode_enum fuzz_mode, picoquic_quic_config_t* config, uint64_t duration_max)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    uint64_t current_time = 0;
    picohttp_server_parameters_t picoquic_file_param = { 0 };
    fuzi_q_ctx_t fuzi_q_ctx = { 0 };

    picoquic_file_param.web_folder = config->www_dir;


    /* Setup the server context */
    if (ret == 0) {
        current_time = picoquic_current_time();
    }
#if 0
    if (ret == 0 && config->token_file_name == NULL) {
        ret = picoquic_config_set_option(config, picoquic_option_Token_File_Name, token_store_filename);
    }
#endif
    if (ret == 0) {
        fuzi_q_ctx.quic = picoquic_create_and_configure(config, picoquic_demo_server_callback, &picoquic_file_param, current_time, NULL);
        if (fuzi_q_ctx.quic == NULL) {
            ret = -1;
        }
        else {
            fuzi_q_ctx.fuzz_mode = fuzz_mode;
            fuzzer_init(&fuzi_q_ctx.fuzz_ctx, duration_max);
            picoquic_set_fuzz(fuzi_q_ctx.quic, basic_fuzzer, &fuzi_q_ctx.fuzz_ctx);
            picoquic_set_key_log_file_from_env(fuzi_q_ctx.quic);

            picoquic_set_alpn_select_fn(fuzi_q_ctx.quic, picoquic_demo_server_callback_select_alpn);

            picoquic_set_mtu_max(fuzi_q_ctx.quic, config->mtu_max);
            if (config->qlog_dir != NULL)
            {
                picoquic_set_qlog(fuzi_q_ctx.quic, config->qlog_dir);
            }
            if (config->performance_log != NULL)
            {
                ret = picoquic_perflog_setup(fuzi_q_ctx.quic, config->performance_log);
            }
#if 0
            if (ret == 0 && config->cnx_id_cbdata != NULL) {
                picoquic_load_balancer_config_t lb_config;
                ret = picoquic_lb_compat_cid_config_parse(&lb_config, config->cnx_id_cbdata, strlen(config->cnx_id_cbdata));
                if (ret != 0) {
                    fprintf(stdout, "Cannot parse the CNX_ID config policy: %s.\n", config->cnx_id_cbdata);
                }
                else {
                    ret = picoquic_lb_compat_cid_config(fuzi_q_ctx.quic, &lb_config);
                    if (ret != 0) {
                        fprintf(stdout, "Cannot set the CNX_ID config policy: %s.\n", config->cnx_id_cbdata);
                    }
                }
            }
#endif
        }
    }

    if (ret == 0) {
        /* Wait for packets */
#if _WINDOWS
        ret = picoquic_packet_loop_win(fuzi_q_ctx.quic, config->server_port, 0, config->dest_if,
            config->socket_buffer_size, fuzi_q_server_loop_cb, &fuzi_q_ctx);
#else
        ret = picoquic_packet_loop(fuzi_q_ctx.quic, config->server_port, 0, config->dest_if,
            config->socket_buffer_size, config->do_not_use_gso, fuzi_q_server_loop_cb, &fuzi_q_ctx);
#endif
    }

    /* And exit */
    printf("Server exit, ret = 0x%x\n", ret);

    if (fuzi_q_ctx.quic != NULL) {
        picoquic_free(fuzi_q_ctx.quic);
    }

    return ret;
}
