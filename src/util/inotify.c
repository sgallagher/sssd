#include <talloc.h>
#include <errno.h>
#include <sys/inotify.h>
#include <sys/time.h>

#include "util/inotify.h"
#include "util/util.h"

#define DFL_BURST_RATE 1

struct snotify_cb_ctx {
    int wd;
    snotify_cb_fn fn;
    uint32_t mask;
    void *pvt;

    struct snotify_cb_ctx *next;
    struct snotify_cb_ctx *prev;

    struct snotify_ctx *snctx;
};

struct snotify_int_cb_ctx {
    struct snotify_ctx *snctx;
};

struct snotify_ctx {
    struct tevent_context *ev;

    /* FIXME - in future, optimize this by moving the fd/filename
     * pair into a global structure so that if multiple places
     * watch the same file, we only setup a single inotify
     */
    const char *filename;
    int burst_rate;

    int inotify_fd;
    struct tevent_fd *tfd;

    bool update_scheduled;
    uint32_t caught_flags;
    struct snotify_cb_ctx *cblist;

    TALLOC_CTX *parent_ctx;
    struct snotify_int_cb_ctx *int_cb_ctx;
};

static int snotify_ctx_destructor(void *memptr)
{
    struct snotify_ctx *snctx;

    snctx = talloc_get_type(memptr, struct snotify_ctx);
    if (snctx == NULL) {
        return 1;
    }

    if (snctx->inotify_fd != -1) {
        close(snctx->inotify_fd);
    }
    /* frees callbacks which remove themselves from the list when freed */
    return 0;
}

static void snotify_process_callbacks(struct tevent_context *ev,
                                      struct tevent_timer *te,
                                      struct timeval t,
                                      void *ptr)
{
    struct snotify_ctx *snctx;
    struct snotify_cb_ctx *cb;
    uint32_t caught_flags;

    talloc_free(te);

    snctx = talloc_get_type(ptr, struct snotify_ctx);
    if (snctx == NULL) {
        return;
    }

    snctx->update_scheduled = false;
    caught_flags = snctx->caught_flags;
    snctx->caught_flags = 0;

    DLIST_FOR_EACH(cb, snctx->cblist) {
        if (cb->mask & caught_flags) {
            cb->fn(snctx->filename, cb->pvt);
        }
    }
}

static struct snotify_ctx *snotify_reopen(struct snotify_ctx *old_ctx)
{
    struct snotify_ctx *new_ctx = NULL;
    struct snotify_cb_ctx *old_cbi;
    struct snotify_cb_ctx *cb;

    new_ctx = snotify_create(old_ctx->parent_ctx, old_ctx->ev,
                             old_ctx->filename, old_ctx->burst_rate);
    if (new_ctx == NULL) {
        goto done;
    }

    DLIST_FOR_EACH(old_cbi, old_ctx->cblist) {
        cb = snotify_add_watch(new_ctx, old_cbi->mask, old_cbi->fn, old_cbi->pvt);
        if (cb == NULL) {
            talloc_zfree(new_ctx);
            goto done;
        }
    }

done:
    talloc_zfree(old_ctx);
    return new_ctx;
}

static void snotify_internal_cb(struct tevent_context *ev,
                                struct tevent_fd *fde,
                                uint16_t flags, void *data)
{
    struct timeval tv;
    struct snotify_ctx *snctx;
    struct snotify_int_cb_ctx *icb;
    struct tevent_timer *te;
    struct inotify_event in_event;
    ssize_t len;

    icb = talloc_get_type(data, struct snotify_int_cb_ctx);
    if (icb == NULL) {
        return;
    }
    snctx = icb->snctx;

    ZERO_STRUCT(in_event);
    len = sss_atomic_read_s(snctx->inotify_fd, &in_event,
                            sizeof(struct inotify_event));
    if (len == -1) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot read inotify_event\n");
        return;
    }

    if (in_event.mask & IN_IGNORED) {
        snctx = snotify_reopen(snctx);
        if (snctx == NULL) {
            return;
        }
    }

    snctx->caught_flags |= in_event.mask;

    if (snctx->update_scheduled == true) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "[%s] already queued for update\n", snctx->filename);
        /* Skip updating. It's already queued for update. */
        return;
    }

    gettimeofday(&tv, NULL);
    tv.tv_sec += snctx->burst_rate;

    te = tevent_add_timer(ev, snctx, tv,
                          snotify_process_callbacks,
                          snctx);
    if (te == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to queue file update!\n");
        return;
    }
}

struct snotify_ctx *snotify_create(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   const char *filename,
                                   int burst_rate)
{
    errno_t ret;
    struct snotify_ctx *snctx;

    snctx = talloc_zero(mem_ctx, struct snotify_ctx);
    if (snctx == NULL) {
        return NULL;
    }

    snctx->filename = talloc_strdup(snctx, filename);
    if (snctx->filename == NULL) {
        talloc_free(snctx);
        return NULL;
    }

    snctx->burst_rate = burst_rate > 0 ? burst_rate : DFL_BURST_RATE;
    snctx->inotify_fd = -1;
    snctx->parent_ctx = mem_ctx;
    snctx->ev = ev;
    talloc_set_destructor((TALLOC_CTX *)snctx, snotify_ctx_destructor);

    snctx->int_cb_ctx = talloc(snctx, struct snotify_int_cb_ctx);
    if (snctx->int_cb_ctx == NULL) {
        talloc_free(snctx->int_cb_ctx);
        return NULL;
    }
    snctx->int_cb_ctx->snctx = snctx;

    snctx->inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (snctx->inotify_fd == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
               "inotify_init1 failed: %d: %s\n", ret, strerror(ret));
        talloc_free(snctx);
        return NULL;
    }

    snctx->tfd = tevent_add_fd(ev, snctx, snctx->inotify_fd,
                               TEVENT_FD_READ, snotify_internal_cb,
                               snctx->int_cb_ctx);
    if (snctx->tfd == NULL) {
        talloc_free(snctx);
        return NULL;
    }

    return snctx;
}

static int snotify_cb_ctx_destructor(void *memptr)
{
    struct snotify_cb_ctx *cb_ctx;

    cb_ctx = talloc_get_type(memptr, struct snotify_cb_ctx);
    if (cb_ctx == NULL) {
        return 1;
    }

    DLIST_REMOVE(cb_ctx->snctx->cblist, cb_ctx);
    return 0;
}

struct snotify_cb_ctx *snotify_add_watch(struct snotify_ctx *snctx,
                                         uint32_t mask,
                                         snotify_cb_fn fn,
                                         void *pvt)
{
    struct snotify_cb_ctx *cb_ctx;

    cb_ctx = talloc_zero(snctx, struct snotify_cb_ctx);
    if (cb_ctx == NULL) {
        return NULL;
    }

    cb_ctx->fn = fn;
    cb_ctx->mask = mask;
    cb_ctx->pvt = pvt;
    cb_ctx->snctx = snctx;
    cb_ctx->wd = inotify_add_watch(snctx->inotify_fd, snctx->filename, mask);
    if (cb_ctx->wd == -1) {
        talloc_free(cb_ctx);
        return NULL;
    }

    DLIST_ADD_END(snctx->cblist, cb_ctx, struct snotify_cb_ctx *);
    talloc_set_destructor((TALLOC_CTX *)cb_ctx, snotify_cb_ctx_destructor);
    return cb_ctx;
}
