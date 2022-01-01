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

#include <stdlib.h>
#include <string.h>
#include <picoquic.h>
#include <picoquic_utils.h>
#include <picoquic_set_textlog.h>
#include <picoquic_set_binlog.h>

#include "fuzi_q.h"
#include "fuzi_q_tests.h"
#ifdef _WINDOWS
#ifdef _WINDOWS64
#define fuzi_q_PICOQUIC_DEFAULT_SOLUTION_DIR "..\\..\\..\\picoquic\\"
#define fuzi_q_DEFAULT_SOLUTION_DIR "..\\..\\"
#else
#define fuzi_q_PICOQUIC_DEFAULT_SOLUTION_DIR "..\\..\\picoquic\\"
#define fuzi_q_DEFAULT_SOLUTION_DIR "..\\"
#endif
#else
#define fuzi_q_PICOQUIC_DEFAULT_SOLUTION_DIR "../picoquic/"
#define fuzi_q_DEFAULT_SOLUTION_DIR "./"
#endif

char const* fuzi_q_test_picoquic_solution_dir = fuzi_q_PICOQUIC_DEFAULT_SOLUTION_DIR;
char const* fuzi_q_test_solution_dir = fuzi_q_DEFAULT_SOLUTION_DIR;


/* Basic test, place holder for now. */
int fuzi_q_basic_test()
{
    return 1;
}
