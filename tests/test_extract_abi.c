/* Regression test for ttdcapa_extract_options' tail: the version-skew shim and the
 * cancellation contract. Both fail silently, which is why they are worth a test.
 *
 *   1. An "old host" sending struct_size = 104 with junk in its tail padding must NOT get the
 *      seeking pass. This is what `reserved0` is for: without it, `recover_strings` would sit
 *      at offset 100 inside the padding an old host never initialises, sizeof would be
 *      unchanged at 104, struct_size could not tell the two layouts apart, and copyOptions
 *      would read that junk as a set flag -- turning on, for a caller that never asked, the
 *      single most expensive thing the pass can do. The test fills the padding with 0xCC to
 *      prove it cannot.
 *   2. A new host setting recover_strings = 1 must run the seeking pass.
 *   3. Cancelling during the seeking pass must return TTDCAPA_E_CANCELLED, not OK, matching
 *      the promise in ttdcapa.h that a cancelled pass produces no output.
 *   4. The same, but arming the predicate only on its 50th call. The recovery pass polls
 *      every iteration; polling on the sweep's 8192-event interval instead would call the
 *      predicate exactly once over a few hundred misses, so this case could never fire.
 *
 * Build it the way examples/embed-demo.c is built (see docs/EMBEDDING.md), from ttd/:
 *
 *     cl /nologo /W4 /I include ..\tests\test_extract_abi.c ^
 *        bin\x64\Release\ttdcapa.lib /Fe:bin\x64\Release\test_extract_abi.exe
 *     bin\x64\Release\test_extract_abi.exe <trace.run>
 *
 * It needs a trace with string arguments the sweep cannot read, which every trace in this
 * work has; it prints PASS or FAIL per case. Expect it to take a few minutes, since cases
 * 1 and 2 replay the trace and cases 3 and 4 replay it up to the recovery pass.
 */
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "ttdcapa.h"

#define OLD_STRUCT_SIZE 104u

static int saw_return_pass;
static int saw_seek_pass;
static int cancel_when_seeking;
static int cancel_armed;
static int cancel_after_n_polls;  /* 0 = disabled */
static int polls;

static void __cdecl on_log(void* user, ttdcapa_log_level level, const char* msg) {
    (void)user; (void)level;
    if (strstr(msg, "at their call's return") != NULL) saw_return_pass = 1;
    if (strstr(msg, "Recovering ") != NULL && strstr(msg, "string parameter") != NULL) {
        saw_seek_pass = 1;
        if (cancel_when_seeking) cancel_armed = 1;
    }
}

static int __cdecl on_cancel(void* user) {
    (void)user;
    if (!cancel_armed) return 0;
    if (cancel_after_n_polls == 0) return 1;
    /* Only cancel once the recovery loop has polled us this many times. With a poll
     * interval of 8192 over a few hundred misses the predicate is called exactly once,
     * so this can never fire -- which is the defect being tested. */
    return (++polls >= cancel_after_n_polls) ? 1 : 0;
}

static void reset(void) {
    saw_return_pass = saw_seek_pass = cancel_armed = polls = 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) { printf("usage: abitest <trace.run>\n"); return 2; }

    /* --- 1. old host: 104 bytes, tail padding deliberately dirty ------------- */
    /* The free return-pass recovery still runs for everyone; only the seeking pass is
       gated, so this asserts return_pass but not seek_pass. */
    {
        unsigned char raw[sizeof(ttdcapa_extract_options)];
        ttdcapa_extract_options* o = (ttdcapa_extract_options*)raw;
        ttdcapa_status st;

        memset(raw, 0xCC, sizeof(raw));   /* every byte junk, including the padding */
        memset(raw, 0, OLD_STRUCT_SIZE);  /* ...then zero only what an old host fills */
        memset(raw + offsetof(ttdcapa_extract_options, reserved0), 0xCC, 4); /* its padding */
        o->struct_size = OLD_STRUCT_SIZE;
        o->common.trace_path = argv[1];
        o->common.log = on_log;
        o->verbose = 1;
        o->max_calls = 2000;

        reset();
        st = ttdcapa_extract_report(o, NULL);
        printf("old-host (struct_size=%u, dirty padding): status=%d seek_pass=%d return_pass=%d -> %s\n",
               OLD_STRUCT_SIZE, (int)st, saw_seek_pass, saw_return_pass,
               (st == TTDCAPA_OK && !saw_seek_pass && saw_return_pass) ? "PASS" : "FAIL");
    }

    /* --- 2. new host asking for the seeking pass ----------------------------- */
    {
        ttdcapa_extract_options o;
        ttdcapa_status st;
        memset(&o, 0, sizeof(o));
        o.struct_size = sizeof(o);
        o.common.trace_path = argv[1];
        o.common.log = on_log;
        o.verbose = 1;
        o.recover_strings = 1;

        reset();
        st = ttdcapa_extract_report(&o, NULL);
        printf("new-host recover_strings=1:                  status=%d seek_pass=%d return_pass=%d -> %s\n",
               (int)st, saw_seek_pass, saw_return_pass,
               (st == TTDCAPA_OK && saw_seek_pass) ? "PASS" : "FAIL");
    }

    /* --- 3. cancelling inside the seeking pass ------------------------------- */
    {
        ttdcapa_extract_options o;
        ttdcapa_status st;
        memset(&o, 0, sizeof(o));
        o.struct_size = sizeof(o);
        o.common.trace_path = argv[1];
        o.common.log = on_log;
        o.common.cancel = on_cancel;
        o.verbose = 1;
        o.recover_strings = 1;  /* the pass being cancelled is the opt-in one */

        reset();
        cancel_when_seeking = 1;
        st = ttdcapa_extract_report(&o, NULL);
        cancel_when_seeking = 0;
        printf("cancel during the seeking pass:              status=%d (E_CANCELLED=%d) -> %s\n",
               (int)st, (int)TTDCAPA_E_CANCELLED,
               (st == TTDCAPA_E_CANCELLED) ? "PASS" : "FAIL");
    }

    /* --- 4. the same, but only on the 50th poll: proves the loop polls per iteration */
    {
        ttdcapa_extract_options o;
        ttdcapa_status st;
        memset(&o, 0, sizeof(o));
        o.struct_size = sizeof(o);
        o.common.trace_path = argv[1];
        o.common.log = on_log;
        o.common.cancel = on_cancel;
        o.verbose = 1;
        o.recover_strings = 1;  /* the pass being cancelled is the opt-in one */

        reset();
        cancel_when_seeking = 1;
        cancel_after_n_polls = 50;
        st = ttdcapa_extract_report(&o, NULL);
        cancel_when_seeking = 0;
        cancel_after_n_polls = 0;
        printf("cancel on the 50th poll of the seeking pass: status=%d polls=%d -> %s\n",
               (int)st, polls, (st == TTDCAPA_E_CANCELLED && polls >= 50) ? "PASS" : "FAIL");
    }

    return 0;
}
