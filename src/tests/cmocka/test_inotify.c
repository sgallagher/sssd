/*
    Copyright (C) 2016 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <talloc.h>
#include <popt.h>

#include "limits.h"
#include "util/io.h"
#include "util/inotify.h"
#include "util/util.h"
#include "tests/common.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define FILE_TEMPLATE TESTS_PATH"/test_inotify.XXXXXX"

struct inotify_test_ctx {
    char *filename;

    int ncb;
    int threshold;

    struct sss_test_ctx *tctx;
};

static int inotify_test_setup(void **state)
{
    struct inotify_test_ctx *ctx;
    int fd;

    ctx = talloc_zero(NULL, struct inotify_test_ctx);
    if (ctx == NULL) {
        return 1;
    }

    ctx->tctx = create_ev_test_ctx(ctx);
    if (ctx->tctx == NULL) {
        talloc_free(ctx);
        return 1;
    }

    ctx->filename = talloc_strdup(ctx, "test_inotify.XXXXXX");
    if (ctx->filename == NULL) {
        talloc_free(ctx);
        return 1;
    }

    fd = mkstemp(ctx->filename);
    if (fd == -1) {
        talloc_free(ctx);
        return 1;
    }
    close(fd);

    *state = ctx;
    return 0;
}

static int inotify_test_teardown(void **state)
{
    struct inotify_test_ctx *ctx = talloc_get_type_abort(*state,
                                                     struct inotify_test_ctx);
    int ret;

    ret = unlink(ctx->filename);
    if (ret == -1) {
        return 1;
    }

    talloc_free(ctx);
    return 0;
}

static void file_mod_op(struct tevent_context *ev,
                        struct tevent_timer *te,
                        struct timeval t,
                        void *ptr)
{
    struct inotify_test_ctx *test_ctx = talloc_get_type_abort(ptr,
                                                struct inotify_test_ctx);
    FILE *f;

    talloc_free(te);

    f = fopen(test_ctx->filename, "w");
    if (f == NULL) {
        test_ctx->tctx->error = errno;
        test_ctx->tctx->done = true;
        return;
    }

    fprintf(f, "%s\n", test_ctx->filename);
    fflush(f);
    fclose(f);
}

static int inotify_mod_cb1(const char *filename, void *pvt)
{
    struct inotify_test_ctx *test_ctx = talloc_get_type_abort(pvt,
                                                struct inotify_test_ctx);

    test_ctx->ncb++;
    return EOK;
}

static int inotify_mod_cb2(const char *filename, void *pvt)
{
    struct inotify_test_ctx *test_ctx = talloc_get_type_abort(pvt,
                                                struct inotify_test_ctx);

    test_ctx->ncb++;
    if (test_ctx->ncb == test_ctx->threshold) {
        test_ctx->tctx->done = true;
        return EOK;
    }

    return EINVAL;
}

static void test_inotify_mod(void **state)
{
    struct inotify_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct inotify_test_ctx);
    struct snotify_ctx *ctx;
    struct snotify_cb_ctx *cb_ctx1;
    struct snotify_cb_ctx *cb_ctx2;
    struct timeval tv;
    struct tevent_timer *te;
    errno_t ret;

    ctx = snotify_create(test_ctx, test_ctx->tctx->ev,
                         test_ctx->filename, 0);
    assert_non_null(ctx);

    cb_ctx1 = snotify_add_watch(ctx, IN_MODIFY, inotify_mod_cb1, test_ctx);
    assert_non_null(cb_ctx1);

    cb_ctx2 = snotify_add_watch(ctx, IN_MODIFY, inotify_mod_cb2, test_ctx);
    assert_non_null(cb_ctx2);

    gettimeofday(&tv, NULL);
    tv.tv_usec += 200;

    test_ctx->threshold = 2;

    te = tevent_add_timer(test_ctx->tctx->ev, test_ctx,
                          tv, file_mod_op, test_ctx);
    if (te == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to queue file update!\n");
        return;
    }

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, EOK);

    talloc_zfree(cb_ctx1);
    test_ctx->ncb = 0;
    test_ctx->threshold = 1;
    test_ctx->tctx->done = false;

    gettimeofday(&tv, NULL);
    tv.tv_usec += 200;

    te = tevent_add_timer(test_ctx->tctx->ev, test_ctx,
                          tv, file_mod_op, test_ctx);
    if (te == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to queue file update!\n");
        return;
    }

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, EOK);

    talloc_free(ctx);
}

static int inotify_mv_cb1(const char *filename, void *pvt)
{
    struct inotify_test_ctx *test_ctx = talloc_get_type_abort(pvt,
                                                struct inotify_test_ctx);

    test_ctx->ncb++;
    if (test_ctx->ncb == test_ctx->threshold) {
        test_ctx->tctx->done = true;
        return EOK;
    }

    return EOK;
}

static void file_mv_op(struct tevent_context *ev,
                       struct tevent_timer *te,
                       struct timeval t,
                       void *ptr)
{
    struct inotify_test_ctx *test_ctx = talloc_get_type_abort(ptr,
                                                struct inotify_test_ctx);
    FILE *f;
    int fd;
    char src_tmp_file[] = "test_inotify_src.XXXXXX";
    int ret;

    talloc_free(te);

    fd = mkstemp(src_tmp_file);
    if (fd == -1) {
        test_ctx->tctx->error = errno;
        test_ctx->tctx->done = true;
        return;
    }

    f = fdopen(fd, "w");
    if (f == NULL) {
        close(fd);
        unlink(src_tmp_file);
        test_ctx->tctx->error = errno;
        test_ctx->tctx->done = true;
        return;
    }

    fprintf(f, "%s\n", test_ctx->filename);
    fflush(f);
    fclose(f);

    ret = rename(src_tmp_file, test_ctx->filename);
    if (ret == -1) {
        unlink(src_tmp_file);
        test_ctx->tctx->error = errno;
        test_ctx->tctx->done = true;
        return;
    }
}

static void test_inotify_mv(void **state)
{
    struct inotify_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct inotify_test_ctx);
    struct snotify_ctx *ctx;
    struct snotify_cb_ctx *cb_ctx1;
    struct timeval tv;
    struct tevent_timer *te;
    errno_t ret;

    test_ctx->threshold = 1;

    ctx = snotify_create(test_ctx, test_ctx->tctx->ev,
                         test_ctx->filename, 0);
    assert_non_null(ctx);

    cb_ctx1 = snotify_add_watch(ctx, IN_MODIFY | IN_IGNORED,
                                inotify_mv_cb1, test_ctx);
    assert_non_null(cb_ctx1);

    gettimeofday(&tv, NULL);
    tv.tv_usec += 200;
    te = tevent_add_timer(test_ctx->tctx->ev, test_ctx,
                          tv, file_mv_op, test_ctx);
    if (te == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to queue file update!\n");
        return;
    }

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

int main(int argc, const char *argv[])
{
    int no_cleanup = 0;
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
         _("Do not delete the test database after a test run"), NULL },
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_inotify_mv,
                                        inotify_test_setup,
                                        inotify_test_teardown),
        cmocka_unit_test_setup_teardown(test_inotify_mod,
                                        inotify_test_setup,
                                        inotify_test_teardown),
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
       default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    DEBUG_CLI_INIT(debug_level);

    return cmocka_run_group_tests(tests, NULL, NULL);
}
