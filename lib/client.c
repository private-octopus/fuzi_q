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
#include <picoquic.h>
#include <picoquic_internal.h>
#include <picoquic_packet_loop.h>
#include <autoqlog.h>
#include <performance_log.h>
#include <tls_api.h>
#include "fuzi_q.h"

/* The fuzzer can be used with multiple applications, with multiple ALPN.
 * There is no application specific code in the fuzzer. This means the 
 * picoquic handling and context handling is pretty much the same as 
 * what is found in "picoquicdemo":
 * - For server side fuzzer, the context is set according to the ALPN 
 *   presented by the client, using `picoquic_demo_server_callback` and
 *   `picoquic_demo_server_callback_select_alpn`
 * - For client side fuzzer, the application context is selected
 *   when setting the connection based on user selected ALPN, or
 *   by default H09 (hq-interop).
 * The client behavior for the fuzzer is not the same as the demo,
 * in particular because the fuzzer will attempt a larger number of
 * connections, some simultaneous. The client will need to:
 * - Start new connections with the selected ALPN whenever the
 *   current number of open connections falls below a threshold.
 * - Start a variable number of streams for each connection,
 *   which can be either downloads or uploads.
 * This is embedded in the client application logic, which
 * should be similar to the "scenario" logic used in the picoquic
 * demo app. One solution might be to randomly generate scenarios
 * when the client is created.
 */

/* Clear a connection context */
void fuzi_q_release_connection(fuzi_q_cnx_ctx_t* cnx_ctx)
{
    if (cnx_ctx->quicperf_ctx != NULL) {
        quicperf_delete_ctx(cnx_ctx->quicperf_ctx);
    }
    picoquic_demo_client_delete_context(&cnx_ctx->callback_ctx);
    if (cnx_ctx->cnx_client != NULL) {
        picoquic_delete_cnx(cnx_ctx->cnx_client);
    }
    memset(cnx_ctx, 0, sizeof(fuzi_q_cnx_ctx_t));
}

/* Mark connection active */
void fuzi_q_mark_active(fuzi_q_ctx_t* fuzi_q_ctx, picoquic_connection_id_t* icid, uint64_t current_time, int was_fuzzed)
{
    for (size_t i = 0; i < fuzi_q_ctx->nb_cnx_ctx; i++) {
        if (fuzi_q_ctx->cnx_ctx[i].cnx_client != NULL &&
            picoquic_compare_connection_id(icid, &fuzi_q_ctx->cnx_ctx[i].icid) == 0) {
            fuzi_q_ctx->cnx_ctx[i].next_time = current_time + FUZI_Q_MAX_SILENCE;
            fuzi_q_ctx->cnx_ctx[i].was_fuzzed |= was_fuzzed;
            break;
        }
    }
}

/* Start client connection */
int fuzi_q_start_connection(fuzi_q_ctx_t* fuzi_q_ctx, fuzi_q_cnx_ctx_t* cnx_ctx, uint64_t current_time)
{
    /* Create the client connection, from parameters in fuzi_q context. */
    int ret = 0;
    char const* alpn = fuzi_q_ctx->alpn;
    uint32_t proposed_version = fuzi_q_ctx->proposed_version;
    char const* ticket_alpn = NULL;
    uint32_t ticket_version = 0;
    /* Create a predictable and random ICID */
    fuzzer_random_cid(&fuzi_q_ctx->fuzz_ctx, &cnx_ctx->icid);
    /* Try pick the ALPN and version from tickets if there are any */

    if (picoquic_demo_client_get_alpn_and_version_from_tickets(fuzi_q_ctx->quic, PICOQUIC_TEST_SNI, alpn,
        proposed_version, &ticket_alpn, &ticket_version) == 0) {
        if (ticket_version != 0) {
            proposed_version = ticket_version;
        }
        if (ticket_alpn != NULL) {
            alpn = ticket_alpn;
        }
    }
    /* Create a client connection */
    cnx_ctx->cnx_client = picoquic_create_cnx(fuzi_q_ctx->quic, cnx_ctx->icid, picoquic_null_connection_id,
        (struct sockaddr*)&fuzi_q_ctx->server_address, current_time,
        proposed_version, PICOQUIC_TEST_SNI, alpn, 1);

    if (cnx_ctx->cnx_client == NULL) {
        ret = -1;
    }
    else {
        if (fuzi_q_ctx->is_quicperf) {
            cnx_ctx->quicperf_ctx = quicperf_create_ctx(fuzi_q_ctx->client_scenario_text, stderr);
            if (cnx_ctx->quicperf_ctx != NULL) {
                picoquic_set_callback(cnx_ctx->cnx_client, quicperf_callback, cnx_ctx->quicperf_ctx);
            }
            else {
                ret = -1;
            }
        }
        else {
            ret = picoquic_demo_client_initialize_context(&cnx_ctx->callback_ctx, fuzi_q_ctx->client_sc, fuzi_q_ctx->client_sc_nb,
                NULL, 1, 0);
            if (ret == 0) {
                cnx_ctx->callback_ctx.out_dir = fuzi_q_ctx->out_dir;
                cnx_ctx->callback_ctx.last_interaction_time = current_time;
                cnx_ctx->callback_ctx.no_print = 1;
                picoquic_set_callback(cnx_ctx->cnx_client, picoquic_demo_client_callback, &cnx_ctx->callback_ctx);

                /* Requires TP grease and enable options for interop tests */
                cnx_ctx->cnx_client->grease_transport_parameters = 1;
                cnx_ctx->cnx_client->local_parameters.enable_time_stamp = 3;
                cnx_ctx->cnx_client->local_parameters.do_grease_quic_bit = 1;

                if (cnx_ctx->callback_ctx.tp != NULL) {
                    picoquic_set_transport_parameters(cnx_ctx->cnx_client, cnx_ctx->callback_ctx.tp);
                }
            }
        }

        if (ret == 0){
            if (fuzi_q_ctx->config != NULL) {
                if (fuzi_q_ctx->config->large_client_hello) {
                    cnx_ctx->cnx_client->test_large_chello = 1;
                }
            }

            if (fuzi_q_ctx->desired_version != 0) {
                picoquic_set_desired_version(cnx_ctx->cnx_client, fuzi_q_ctx->desired_version);
            }
        }

        if (ret == 0) {
            cnx_ctx->next_time = current_time + FUZI_Q_MAX_SILENCE;
            ret = picoquic_start_client_cnx(cnx_ctx->cnx_client);
        }
        if (ret == 0 && !fuzi_q_ctx->is_quicperf) {
            if (picoquic_is_0rtt_available(cnx_ctx->cnx_client) && (fuzi_q_ctx->proposed_version & 0x0a0a0a0a) != 0x0a0a0a0a) {
                cnx_ctx->zero_rtt_available = 1;
                /* Start the download scenario */
                ret = picoquic_demo_client_start_streams(cnx_ctx->cnx_client, &cnx_ctx->callback_ctx, PICOQUIC_DEMO_STREAM_ID_INITIAL);
            }
        }
    }

    return ret;
}

static const char* test_scenario_default = "0:index.html;4:test.html;8:/1234567;12:main.jpg;16:war-and-peace.txt;20:en/latest/;24:/file-123K";

/* Set quic context for client run.
 * 
 */
int fuzi_q_set_client_context(fuzi_q_mode_enum fuzz_mode, fuzi_q_ctx_t* fuzi_q_ctx, const char* ip_address_text, int server_port,
    picoquic_quic_config_t* config, size_t nb_cnx_required, uint64_t duration_max, picoquic_connection_id_t* init_cid,
    char const* client_scenario_text, uint64_t* virtual_time)
{
    int ret = 0;
    uint64_t current_time = (virtual_time == NULL)?picoquic_current_time(): *virtual_time;
    size_t nb_cnx_ctx = 1;

    fuzi_q_ctx->fuzz_mode = fuzz_mode;
    fuzi_q_ctx->config = config;
    fuzi_q_ctx->up_time_interval = 60000000; /* Use 1 minute by default -- hanshake timer is set to 30 seconds. */
    fuzi_q_ctx->cnx_duration_min = UINT64_MAX;
    if (config != NULL) {
        fuzi_q_ctx->socket_buffer_size = config->socket_buffer_size;
        fuzi_q_ctx->alpn = config->alpn;
        fuzi_q_ctx->sni = config->sni;
        fuzi_q_ctx->proposed_version = config->proposed_version;
        fuzi_q_ctx->desired_version = config->desired_version;
        nb_cnx_ctx = config->nb_connections;
    }

    fuzi_q_ctx->end_of_time = (duration_max == 0)?UINT64_MAX:current_time + duration_max*1000000;
    fuzi_q_ctx->nb_cnx_required = (nb_cnx_required == 0)?SIZE_MAX: nb_cnx_required;
    fuzi_q_ctx->next_success_time = current_time + fuzi_q_ctx->up_time_interval;

    if (fuzi_q_ctx->alpn != NULL && strcmp(fuzi_q_ctx->alpn, QUICPERF_ALPN) == 0) {
        /* Set a QUICPERF client */
        fuzi_q_ctx->is_quicperf = 1;
        fprintf(stdout, "Getting ready to fuzz QUICPERF server\n");
    }
    else {
        if (client_scenario_text == NULL) {
            client_scenario_text = test_scenario_default;
        }

        fprintf(stdout, "Testing scenario: <%s>\n", client_scenario_text);
        ret = demo_client_parse_scenario_desc(client_scenario_text, &fuzi_q_ctx->client_sc_nb, &fuzi_q_ctx->client_sc);
        if (ret != 0) {
            fprintf(stdout, "Cannot parse the specified scenario.\n");
        }
    }

    /* Get the server address */
    if (ret == 0) {
        int is_name = 0;

        ret = picoquic_get_server_address(ip_address_text, server_port, &fuzi_q_ctx->server_address, &is_name);
        if (ret == 0 && fuzi_q_ctx->sni == NULL && is_name != 0) {
            fuzi_q_ctx->sni = ip_address_text;
        }
    }

    /* Create QUIC context */
    if (ret == 0) {
        fuzi_q_ctx->quic = picoquic_create_and_configure(fuzi_q_ctx->config, NULL, NULL, current_time, virtual_time);
        if (fuzi_q_ctx->quic == NULL) {
            ret = -1;
        }
        else {
            fuzi_q_fuzzer_init(&fuzi_q_ctx->fuzz_ctx, init_cid, fuzi_q_ctx->quic);
            fuzi_q_ctx->fuzz_ctx.parent = fuzi_q_ctx;
            if (fuzz_mode != fuzi_q_mode_clean) {
                picoquic_set_fuzz(fuzi_q_ctx->quic, fuzi_q_fuzzer, &fuzi_q_ctx->fuzz_ctx);
            }
            picoquic_set_key_log_file_from_env(fuzi_q_ctx->quic);

            if (fuzi_q_ctx->config != NULL) {
                if (fuzi_q_ctx->config->qlog_dir != NULL)
                {
                    picoquic_set_qlog(fuzi_q_ctx->quic, fuzi_q_ctx->config->qlog_dir);
                }

                if (fuzi_q_ctx->config->performance_log != NULL)
                {
                    ret = picoquic_perflog_setup(fuzi_q_ctx->quic, fuzi_q_ctx->config->performance_log);
                }
            }
        }
    }

    /* Create empty connection contexts */
    if (ret == 0) {
        fuzi_q_ctx->cnx_ctx = (fuzi_q_cnx_ctx_t*)malloc(sizeof(fuzi_q_cnx_ctx_t) * nb_cnx_ctx);
        if (fuzi_q_ctx->cnx_ctx == NULL) {
            ret = -1;
        }
        else {
            memset(fuzi_q_ctx->cnx_ctx, 0, sizeof(fuzi_q_cnx_ctx_t) * nb_cnx_ctx);
            fuzi_q_ctx->nb_cnx_ctx = nb_cnx_ctx;
        }
    }

    return ret;
}

void fuzi_q_release_client_context(fuzi_q_ctx_t* fuzi_q_ctx)
{
    if (fuzi_q_ctx->cnx_ctx != NULL) {
        for (size_t i = 0; i < fuzi_q_ctx->nb_cnx_ctx; i++) {
            fuzi_q_release_connection(&fuzi_q_ctx->cnx_ctx[i]);
        }
        free(fuzi_q_ctx->cnx_ctx);
        fuzi_q_ctx->cnx_ctx = NULL;
    }
    fuzi_q_ctx->nb_cnx_ctx = 0;

    if (fuzi_q_ctx->quic != NULL) {
        picoquic_free(fuzi_q_ctx->quic);
        fuzi_q_ctx->quic = NULL;
    }

    if (fuzi_q_ctx->client_sc != NULL) {
        demo_client_delete_scenario_desc(fuzi_q_ctx->client_sc_nb, fuzi_q_ctx->client_sc);
        fuzi_q_ctx->client_sc = NULL;
    }
    fuzi_q_ctx->client_sc_nb = 0;
}

/* Fuzi Q, client loop.
 * Need to maintain a set of connections, as specified by "nb_cnx_ctx". 
 * Need to run until the specified number of trials have been done, or
 * the specified time has elapsed.
 * Need to check that some connections are succeeding. This will have to be 
 * coordinated with the fuzzer logic, e.g., do not fuzz before handshake
 * has succeeded for at least some connections. 
 * TODO: consider migration trials, key update trials.
 */
int fuzi_q_loop_check_cnx(fuzi_q_ctx_t* fuzi_q_ctx, uint64_t current_time, int * is_active)
{
    int ret = 0;
    int nb_active = 0;

    for (size_t i = 0; i < fuzi_q_ctx->nb_cnx_ctx && ret == 0; i++) {
        fuzi_q_cnx_ctx_t* cnx_ctx = &fuzi_q_ctx->cnx_ctx[i];

        if (cnx_ctx->cnx_client != NULL) {
            /* If this is a newly successful connection, update the last success pointer
             * If this is a disconnected connection, clear the app level data.
             */
            picoquic_state_enum cnx_state = picoquic_get_cnx_state(cnx_ctx->cnx_client);
            int should_abandon = 0;

            if (cnx_state == picoquic_state_ready) {
                if (!cnx_ctx->success_observed) {
                    fuzi_q_ctx->next_success_time = current_time + fuzi_q_ctx->up_time_interval;
                    cnx_ctx->success_observed = 1;
                    if (ret == 0 && !cnx_ctx->zero_rtt_available) {
                        if (!fuzi_q_ctx->is_quicperf) {
                            /* Start the download scenario */
                            ret = picoquic_demo_client_start_streams(cnx_ctx->cnx_client, &cnx_ctx->callback_ctx, PICOQUIC_DEMO_STREAM_ID_INITIAL);
                            *is_active = 1;
                        }
                    }
                }
                else if (cnx_ctx->callback_ctx.nb_open_streams == 0) {
                    ret = picoquic_close(cnx_ctx->cnx_client, 0);
                    *is_active = 1;
                }
            }
            if (cnx_ctx->cnx_client->path[0]->nb_retransmit > 2 || current_time >= cnx_ctx->next_time) {
                should_abandon = 1;
            }
            if (cnx_state == picoquic_state_disconnected || should_abandon) {
                uint64_t cnx_duration = current_time - cnx_ctx->cnx_client->start_time;
                if (cnx_duration > fuzi_q_ctx->cnx_duration_max) {
                    fuzi_q_ctx->cnx_duration_max = cnx_duration;
                    fuzi_q_ctx->icid_duration_max.id_len = picoquic_parse_connection_id(cnx_ctx->cnx_client->initial_cnxid.id,
                        cnx_ctx->cnx_client->initial_cnxid.id_len, &fuzi_q_ctx->icid_duration_max);
                }
                if (cnx_duration < fuzi_q_ctx->cnx_duration_min) {
                    fuzi_q_ctx->cnx_duration_min = cnx_duration;
                }
                if (fuzi_q_ctx->fuzz_mode == fuzi_q_mode_client && !cnx_ctx->was_fuzzed) {
                    DBG_PRINTF("Connection stopped without being fuzzed: %02x%02x...", cnx_ctx->icid.id[0], cnx_ctx->icid.id[1]);
                }
                fuzi_q_release_connection(cnx_ctx);
                *is_active = 1;
            }
        }
        if (cnx_ctx->cnx_client == NULL){
            if (current_time >= fuzi_q_ctx->end_of_time) {
                DBG_PRINTF("Abandon fuzz at time = %" PRIu64, current_time);
            } else if (fuzi_q_ctx->nb_cnx_tried < fuzi_q_ctx->nb_cnx_required) {
                /* If the required number of trials is not done, try starting a new connection. */
                fuzi_q_ctx->nb_cnx_tried++;
                ret = fuzi_q_start_connection(fuzi_q_ctx, cnx_ctx, current_time);
                *is_active = 1;
                nb_active++;
            }
        }
        else {
            nb_active++;
        }
    }

    if (ret == 0 && nb_active == 0) {
            ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
    }
    else if (current_time > fuzi_q_ctx->next_success_time) {
        fuzi_q_ctx->server_is_down = 1;
        ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
    }

    return ret;
}

uint64_t fuzi_q_next_time(fuzi_q_ctx_t* fuzi_q_ctx)
{
    uint64_t next_event_time = UINT64_MAX;

    if (fuzi_q_ctx->fuzz_mode == fuzi_q_mode_client) {
        next_event_time = fuzi_q_ctx->end_of_time;
        if (next_event_time > fuzi_q_ctx->next_success_time) {
            next_event_time = fuzi_q_ctx->next_success_time;
        }
        for (size_t i = 0; i < fuzi_q_ctx->nb_cnx_ctx; i++) {
            if (fuzi_q_ctx->cnx_ctx[i].cnx_client != NULL &&
                fuzi_q_ctx->cnx_ctx[i].next_time < next_event_time) {
                next_event_time = fuzi_q_ctx->cnx_ctx[i].next_time;
            }
        }
    }

    return next_event_time;
}

void fuzi_q_check_time(fuzi_q_ctx_t* fuzi_q_ctx, packet_loop_time_check_arg_t* time_check_arg)
{
    uint64_t next_time = time_check_arg->current_time + time_check_arg->delta_t;
    uint64_t next_event_time = fuzi_q_next_time(fuzi_q_ctx);

    if (next_event_time < next_time) {
        time_check_arg->delta_t = next_time - time_check_arg->current_time;
    }
}

int fuzi_q_client_loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode,
    void* callback_ctx, void* callback_arg)
{
    int ret = 0;
    fuzi_q_ctx_t* fuzi_q_ctx = (fuzi_q_ctx_t *)callback_ctx;
    int is_active = 0;

    if (fuzi_q_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        switch (cb_mode) {
        case picoquic_packet_loop_ready:
            if (callback_arg != NULL) {
                picoquic_packet_loop_options_t* options = (picoquic_packet_loop_options_t*)callback_arg;
                options->do_time_check = 1;
            }
            fprintf(stdout, "Waiting for packets.\n");
            break;
        case picoquic_packet_loop_after_receive:
            /* Post receive callback */
            /* TODO: consider migration trials */
            /* TODO: consider key update trials */
            break;
        case picoquic_packet_loop_after_send:
            /* check whether some connections were closed. */
            /* check whether at least one connection succeeded. */
            ret = fuzi_q_loop_check_cnx(fuzi_q_ctx, picoquic_get_quic_time(fuzi_q_ctx->quic), &is_active);
            break;
        case picoquic_packet_loop_port_update:
            break;
        case picoquic_packet_loop_time_check:
            /* Check whether the time to close the app is arriving */
            fuzi_q_check_time(fuzi_q_ctx, (packet_loop_time_check_arg_t*)callback_arg);
            break;
        default:
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            break;
        }
    }
    return ret;
}


/* Fuzi Quic Client
 * TODO: manage loop options like key updates, migrations, etc. 
 */
int fuzi_q_client(fuzi_q_mode_enum fuzz_mode, const char* ip_address_text, int server_port,
    picoquic_quic_config_t* config, size_t nb_cnx_required, uint64_t duration_max,
    picoquic_connection_id_t * init_cid, char const* client_scenario_text)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    fuzi_q_ctx_t fuzi_q_ctx = { 0 };
    int is_active = 0;

    ret = fuzi_q_set_client_context(fuzz_mode, &fuzi_q_ctx, ip_address_text, server_port,
        config, nb_cnx_required, duration_max, init_cid, client_scenario_text, NULL);

    /* Start the client connections */
    if (ret == 0) {
        ret = fuzi_q_loop_check_cnx(&fuzi_q_ctx, picoquic_get_quic_time(fuzi_q_ctx.quic), &is_active);
    }
    /* Wait for packets */
    if (ret == 0) {
#ifdef _WINDOWS
        ret = picoquic_packet_loop_win(fuzi_q_ctx.quic, 0, fuzi_q_ctx.server_address.ss_family, 0,
            (int)fuzi_q_ctx.socket_buffer_size, fuzi_q_client_loop_cb, &fuzi_q_ctx);
#else
        ret = picoquic_packet_loop(fuzi_q_ctx.quic, 0, fuzi_q_ctx.server_address.ss_family, 0,
            fuzi_q_ctx.socket_buffer_size, 0, fuzi_q_client_loop_cb, &fuzi_q_ctx);
#endif
    }

    fprintf(stdout, "Exit after %zu trials, server appears %s.\n", fuzi_q_ctx.nb_cnx_tried,
        (fuzi_q_ctx.server_is_down) ? "down" : "up");
    for (int i = 0; i < fuzzer_cnx_state_max; i++) {
        fprintf(stdout, "State: %d, %zu connections tried, %zu fuzzed, %zu packets fuzzed out of %zu.\n",
            i, fuzi_q_ctx.fuzz_ctx.nb_cnx_tried[i], fuzi_q_ctx.fuzz_ctx.nb_cnx_fuzzed[i],
            fuzi_q_ctx.fuzz_ctx.nb_packets_fuzzed[i],
            fuzi_q_ctx.fuzz_ctx.nb_packets_state[i]);
    }
    fprintf(stdout, "Tried %zu connections (target: %zu). Connection min: %fs, max %fs\n",
        fuzi_q_ctx.nb_cnx_tried, fuzi_q_ctx.nb_cnx_required,
        ((double)fuzi_q_ctx.cnx_duration_min) / 1000000.0,
        ((double)fuzi_q_ctx.cnx_duration_max) / 1000000.0);
    fprintf(stdout, "ID of longest_connection: ");
    for (uint8_t x = 0; x < fuzi_q_ctx.icid_duration_max.id_len; x++) {
        fprintf(stdout, "%02x", fuzi_q_ctx.icid_duration_max.id[x]);
    }
    fprintf(stdout, "\n");

    fuzi_q_release_client_context(&fuzi_q_ctx);

    return ret;
}
