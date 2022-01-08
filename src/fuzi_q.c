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

/* quicr demo app */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WINDOWS
#define WIN32_LEAN_AND_MEAN
#include "getopt.h"
#include <WinSock2.h>
#include <Windows.h>

#define SERVER_CERT_FILE "certs\\cert.pem"
#define SERVER_KEY_FILE  "certs\\key.pem"

#else /* Linux */

#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K
#endif
#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#endif

#include <picoquic.h>
#include <picosocks.h>
#include <picoquic_config.h>
#include <picoquic_packet_loop.h>
#include <autoqlog.h>
#include <performance_log.h>
#include "fuzi_q.h"


void usage()
{
    fprintf(stderr, "fuzi_q: over the net quic fuzzer\n");
    fprintf(stderr, "Usage: fuzi_q <options> [fuzz_mode] [server_name port [scenario]] \n");
    fprintf(stderr, "  fuzz_mode can be one of client, clean or server.");
    fprintf(stderr, "  For the client or clean fuzz_mode, specify server_name and port.\n");
    fprintf(stderr, "  For the server fuzz_mode, use -p to specify the port,\n");
    fprintf(stderr, "  and also -c and -k for certificate and matching private key.\n");
    picoquic_config_usage();
    fprintf(stderr, "fuzi_q options:\n");
    fprintf(stderr, "  -f nb_fuzz_trials     Number of trials to be attempted.\n");
    fprintf(stderr, "  -d duration_max       Duration of the test, in seconds.\n");
    fprintf(stderr, "\nThe scenario argument is same as for picoquicdemo.\n");
    exit(1);
}

int main(int argc, char** argv)
{
    picoquic_quic_config_t config;
    char option_string[512];
    int opt;
    int ret = 0;
    fuzi_q_mode_enum fuzz_mode = 0;
    const char* server_name = NULL;
    int server_port = -1;
    size_t nb_fuzz_trials = 0;
    uint64_t fuzz_duration_max = 0;
    int arg_as_int;
    char const* scenario = NULL;
#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif
    picoquic_config_init(&config);
    memcpy(option_string, "d:f:", 4);
    ret = picoquic_config_option_letters(option_string + 4, sizeof(option_string) - 4, NULL);

    if (ret == 0) {
        /* Get the parameters */
        while ((opt = getopt(argc, argv, option_string)) != -1) {
            switch (opt) {
            case 'd':
                if ((arg_as_int = atoi(optarg)) < 0) {
                    fprintf(stderr, "Invalid value of fuzz duration: %s\n", optarg);
                    usage();
                }
                else {
                    fuzz_duration_max = (uint64_t)arg_as_int;
                }
                break;
            case 'f':
                if ((arg_as_int = atoi(optarg)) < 0) {
                    fprintf(stderr, "Invalid number of fuzz_trials: %s\n", optarg);
                    usage();
                }
                else {
                    nb_fuzz_trials = (size_t)arg_as_int;
                }
                break;
            default:
                if (picoquic_config_command_line(opt, &optind, argc, (char const**)argv, optarg, &config) != 0) {
                    usage();
                }
                break;
            }
        }
    }

    /* Simplified style params */
    if (optind < argc) {
        char const* a_fuzz_mode = argv[optind++];
        if (strcmp(a_fuzz_mode, "client") == 0) {
            fuzz_mode = fuzi_q_mode_client;
        }
        else if (strcmp(a_fuzz_mode, "server") == 0) {
            fuzz_mode = fuzi_q_mode_server;
        }
        else if (strcmp(a_fuzz_mode, "clean") == 0) {
            fuzz_mode = fuzi_q_mode_clean;
        }
        else {
            fprintf(stdout, "Fuzz mode incorrect, %s\n", a_fuzz_mode);
        }
    }
    else {
        fprintf(stdout, "Fuzz mode not specified.\n");
    }

    if (fuzz_mode == fuzi_q_mode_none){
        usage();
    }
    else
    {
        if (fuzz_mode == fuzi_q_mode_client || fuzz_mode == fuzi_q_mode_clean) {
            if (optind + 2 > argc) {
                fprintf(stdout, "Expected server and port after fuzz mode\n");
                usage();
            }
            else {
                server_name = argv[optind++];
                server_port = atoi(argv[optind++]);
                if (server_port <= 0) {
                    fprintf(stderr, "Invalid server port: %s\n", optarg);
                    usage();
                }
            }

            if (optind < argc) {
                scenario = argv[optind++];
            }
        }

        if (optind < argc) {
            fprintf(stderr, "Unexpected arguments: %s\n", argv[optind]);
            usage();
        }
    }

    /* Run */
    if (fuzz_mode == fuzi_q_mode_client || fuzz_mode == fuzi_q_mode_clean) {
        ret = fuzi_q_client(fuzz_mode, server_name, server_port, &config, nb_fuzz_trials, fuzz_duration_max, scenario);
    }
    else {
        ret = fuzi_q_server(fuzz_mode, &config, fuzz_duration_max);
    }
    /* Clean up */
    picoquic_config_clear(&config);
    /* Exit */
    exit(ret);
}
