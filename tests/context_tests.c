/*
* Author: Christian Huitema
* Copyright (c) 2022, Private Octopus, Inc.
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
#include <picoquic_utils.h>
#include "fuzi_q.h"

/* Create a context, add a series of QUIC connections
 * with specified ICID, verify that every ICID is
 * present in table, etc.
 */

picoquic_connection_id_t test_icid[] = {
    {{0, 0, 0, 0}, 0},
    {{0, 0, 0, 0}, 1},
    {{0, 0, 0, 0}, 2},
    {{1, 1, 1, 1, 1, 1, 1}, 7},
    {{1, 1, 1, 1, 1, 1, 1, 1}, 8},
    {{1, 1, 1, 1, 1, 1, 1, 1, 1}, 9},
    {{1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 10},
    {{2, 2, 2, 2, 2, 2, 2}, 7},
    {{2, 2, 2, 2, 2, 2, 2, 2}, 8},
    {{2, 2, 2, 2, 2, 2, 2, 2, 2}, 9},
    {{2, 2, 2, 2, 2, 2, 2, 2, 2, 2}, 10},
};

size_t nb_test_icid = sizeof(test_icid) / sizeof(picoquic_connection_id_t);

int icid_table_check_chain(fuzzer_ctx_t* ctx, size_t nb_expected)
{
    int ret = 0;
    /* Check MRU chain */
    size_t mru_count = 0;
    size_t lru_count = 0;
    fuzzer_icid_ctx_t* next = ctx->icid_mru;
    while (ret == 0) {
        if (next == NULL) {
            if (mru_count < nb_expected) {
                ret = -1;
            }
            break;
        }
        else {
            mru_count++;
            if (mru_count > nb_expected) {
                ret = -1;
                break;
            }
            next = next->icid_after;
        }
    }
    /* Check MRU chain */
    next = ctx->icid_lru;
    while (ret == 0) {
        if (next == NULL) {
            if (lru_count < nb_expected) {
                ret = -1;
            }
            break;
        }
        else {
            lru_count++;
            if (lru_count > nb_expected) {
                ret = -1;
                break;
            }
            next = next->icid_before;
        }
    }
    return ret;
}

int icid_table_test()
{
    int ret = 0;
    uint64_t current_time = 0;
    fuzzer_icid_ctx_t* fuzz_cnx_ctx;
    fuzzer_ctx_t ctx = { 0 };

    fuzi_q_fuzzer_init(&ctx, 0);

    for (int trials = 0; ret == 0 && trials < 3; trials++)
    {
        /* Create once, then check again, and verify that all entries are in the table in the right order */
        for (size_t i = 0; i < nb_test_icid; i++) {
            current_time += 1000;
            (void)fuzzer_get_icid_ctx(&ctx, &test_icid[i], current_time);
            if (ret == 0) {
                ret = icid_table_check_chain(&ctx, ctx.icid_tree.size);
                if (ret != 0) {
                    DBG_PRINTF("Chain invalid after %zu trials, step %zu", trials + 1, i);
                }
            }
        }
        if (ret == 0 && ctx.icid_tree.size != nb_test_icid)
        {
            DBG_PRINTF("Wrong tree size #%zu", ctx.icid_tree.size);
            ret = -1;
        }

        fuzz_cnx_ctx = ctx.icid_lru;

        for (size_t i = 0; ret == 0 && i < nb_test_icid; i++) {
            if (fuzz_cnx_ctx == NULL) {
                DBG_PRINTF("Missing entry #%zu", i);
                ret = -1;
            }
            else if (picoquic_compare_connection_id(&fuzz_cnx_ctx->icid, &test_icid[i]) != 0) {
                DBG_PRINTF("Wrong LRU entry #%zu", i);
                ret = -1;
            }
            else
            {
                fuzz_cnx_ctx = fuzz_cnx_ctx->icid_before;
            }
        }

        if (ret == 0 && fuzz_cnx_ctx != NULL) {
            DBG_PRINTF("%s", "One entry too many!");
            ret = -1;
        }

        if (ret == 0) {
            ret = icid_table_check_chain(&ctx, nb_test_icid);
            if (ret != 0) {
                DBG_PRINTF("Chain invalid after %d trials", trials+1);
            }
        }
    }

    fuzi_q_fuzzer_release(&ctx);
    return ret;
}