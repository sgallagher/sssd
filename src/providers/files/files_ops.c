/*
    SSSD

    Files provider operations

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
#include <dlfcn.h>

#include "providers/files/files_private.h"
#include "util/inotify.h"
#include "util/util.h"

#define FILES_REALLOC_CHUNK 64
#define PWD_BUFSIZE         256
#define PWD_MAXSIZE         1024

struct files_ops_ctx {
    void *dl_handle;

    enum nss_status (*setpwent)(void);
    enum nss_status (*getpwent_r)(struct passwd *result,
                                  char *buffer, size_t buflen,
                                  int *errnop);
    enum nss_status (*endpwent)(void);

    enum nss_status (*setgrent)(void);
    enum nss_status (*getgrent_r)(struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*endgrent)(void);
};

struct files_ctx {
    struct snotify_ctx *pwd_watch;
    struct snotify_ctx *grp_watch;

    struct files_ops_ctx *ops;
};

static struct files_ops_ctx *nss_files_open(TALLOC_CTX *mem_ctx,
                                            const char *lib_location)
{
    struct files_ops_ctx *ctx;

    ctx = talloc(mem_ctx, struct files_ops_ctx);
    if (ctx == NULL) {
        return NULL;
    }

    ctx->dl_handle = dlopen(lib_location, RTLD_NOW);
    if (ctx->dl_handle == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to load %s module with path, error: %s\n",
              lib_location, dlerror());
        goto fail;
    }

    /* FIXME - the proxy provider does practically the same thing,
     * should we generalize?
     */
    ctx->setpwent = dlsym(ctx->dl_handle, "_nss_files_setpwent");
    if (ctx->setpwent == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to load setpwent, error: %s\n", dlerror());
        goto fail;
    }

    ctx->getpwent_r = dlsym(ctx->dl_handle, "_nss_files_getpwent_r");
    if (!ctx->getpwent_r) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to load getpwent, error: %s\n", dlerror());
        goto fail;
    }

    ctx->endpwent = dlsym(ctx->dl_handle, "_nss_files_endpwent");
    if (!ctx->endpwent) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to load endpwent, error: %s\n", dlerror());
        goto fail;
    }

    ctx->setgrent = dlsym(ctx->dl_handle, "_nss_files_setgrent");
    if (ctx->setgrent == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to load setgrent, error: %s\n", dlerror());
        goto fail;
    }

    ctx->getgrent_r = dlsym(ctx->dl_handle, "_nss_files_getgrent_r");
    if (!ctx->getgrent_r) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to load getgrent, error: %s\n", dlerror());
        goto fail;
    }

    ctx->endgrent = dlsym(ctx->dl_handle, "_nss_files_endgrent");
    if (!ctx->endgrent) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to load endgrent, error: %s\n", dlerror());
        goto fail;
    }

    return ctx;

fail:
    talloc_free(ctx);
    return NULL;
}

/* FIXME - we might want to support paging of sorts to avoid allocating
 * all users atop a memory context or only return users that differ from
 * the local storage as a diff to minimize memory spikes
 */
static errno_t sf_users_enumerate(TALLOC_CTX *mem_ctx,
                                  const char *passwd_file,
                                  struct files_id_ctx *id_ctx,
                                  struct passwd ***_users)
{
    errno_t ret;
    ssize_t bufsize = PWD_BUFSIZE;
    ssize_t maxsize;
    char *buffer;
    enum nss_status status;
    struct passwd *pw;
    struct passwd **users;
    size_t n_users;
    TALLOC_CTX *tmp_ctx;
    bool enumerating;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    maxsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (maxsize == -1) {
        maxsize = PWD_MAXSIZE;
    }

    users = talloc_zero_array(tmp_ctx, struct passwd *, FILES_REALLOC_CHUNK);
    if (users == NULL) {
        ret = ENOMEM;
        goto done;
    }
    n_users = FILES_REALLOC_CHUNK;

    /* FIXME - too many pointer dereference levels? */
    status = id_ctx->fctx->ops->setpwent();
    if (status != NSS_STATUS_SUCCESS) {
        /* FIXME - convert to nicer error codes */
        ret = EIO;
        goto done;
    }
    enumerating = true;

    do {
        buffer = talloc_size(tmp_ctx, bufsize);
        if (buffer == NULL) {
            ret = ENOMEM;
            break;
        }
        memset(buffer, 0, sizeof(struct passwd));

        pw = talloc_zero(tmp_ctx, struct passwd);
        if (buffer == NULL) {
            ret = ENOMEM;
            break;
        }

        /* get entry */
        status = id_ctx->fctx->ops->getpwent_r(pw, buffer, bufsize, &ret);
        switch (status) {
        case NSS_STATUS_TRYAGAIN:
            bufsize += PWD_BUFSIZE;
            if (bufsize > maxsize) {
                ret = ERANGE;
                enumerating = false;
                break;
            }
            buffer = talloc_realloc_size(tmp_ctx, buffer, bufsize);
            if (buffer == NULL) {
                ret = ENOMEM;
                enumerating = false;
                break;
            }
        case NSS_STATUS_NOTFOUND:
            /* we are done here */
            DEBUG(SSSDBG_TRACE_LIBS, "User enumeration completed.\n");
            enumerating = false;
            break;
        case NSS_STATUS_SUCCESS:
            DEBUG(SSSDBG_TRACE_LIBS,
                    "User found (%s, %"SPRIuid", %"SPRIgid")\n",
                    pw->pw_name, pw->pw_uid, pw->pw_gid);

            users[n_users] = talloc_steal(users, pw);
            talloc_steal(users, buffer);

            n_users++;
            if (n_users % FILES_REALLOC_CHUNK == 0) {
                users = talloc_realloc(
                            tmp_ctx, users, struct passwd *,
                            talloc_get_size(users) + FILES_REALLOC_CHUNK);
                if (users == NULL) {
                    enumerating = false;
                    break;
                }
            }
            break;
        case NSS_STATUS_UNAVAIL:
            enumerating = false;
            break;
        default:
            ret = EIO;
            DEBUG(SSSDBG_OP_FAILURE,
                  "files -> getpwent_r failed (%d)[%s]\n",
                  ret, sss_strerror(ret));
            break;
        }
    } while (enumerating);

    users[n_users] = NULL;

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sf_groups_enumerate(TALLOC_CTX *mem_ctx,
                                   const char *group_file,
                                   struct group **_groups)
{
    /* Call the ops in loop until we get all the groups, return them atop
     * mem_ctx */
    return EOK;
}

static int sf_passwd_cb(const char *filename, void *pvt)
{
    errno_t ret;
    errno_t tret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct passwd **users;
    struct passwd *pw;
    struct files_id_ctx *id_ctx;
    bool in_transaction = false;

    id_ctx = talloc_get_type(pvt, struct files_id_ctx);
    if (id_ctx == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* FIXME - test no users */
    ret = sf_users_enumerate(tmp_ctx, filename, id_ctx, &users);
    if (ret != EOK) {
        /* FIXME - what if callback fails? This should be configurable
         * at the inotify level
         */
        goto done;
    }

    /* FIXME - save users. We need the domain context here, from pvt */
    ret = sysdb_transaction_start(id_ctx->be->domain->sysdb);
    if (ret != EOK) {
        goto done;
    }

    for (size_t i; users[i]; i++) {
        pw = users[i];

        ret = sysdb_store_user(id_ctx->be->domain,
                               pw->pw_name,
                               pw->pw_passwd,
                               pw->pw_uid,
                               pw->pw_gid,
                               pw->pw_gecos,
                               pw->pw_dir,
                               pw->pw_shell,
                               NULL, NULL, NULL, 0, 0);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = sysdb_transaction_commit(id_ctx->be->domain->sysdb);
    if (ret != EOK) {
        goto done;
    }

    /* FIXME - should saving either trigger an update of /both/ ? Consider
     * the case when someone edits /etc/group, adds a group member and only
     * then edits passwd and adds the user. At least when a user is added/removed
     * we should do both.
     */

    ret = EOK;
done:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(id_ctx->be->domain->sysdb);
        if (tret != EOK) {
            //
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

static int sf_group_cb(const char *filename, void *pvt)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct group *groups;
    struct files_id_ctx *id_ctx;

    id_ctx = talloc_get_type(pvt, struct files_id_ctx);
    if (id_ctx == NULL) {
        return EINVAL;
    }

    ret = sf_groups_enumerate(tmp_ctx, filename, &groups);
    if (ret != EOK) {
        /* FIXME - what if callback fails? This should be configurable
         * at the inotify level
         */
        return ret;
    }

    /* FIXME - save groups. We need the domain context here, from pvt */
    return EOK;
}

static struct snotify_ctx *sf_setup_watch(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          const char *filename,
                                          snotify_cb_fn fn,
                                          struct files_id_ctx *id_ctx)
{
    struct snotify_ctx *sctx = NULL;
    struct snotify_cb_ctx *fcb = NULL;

    sctx = snotify_create(mem_ctx, ev, filename, 0);
    if (sctx == NULL) {
        return NULL;
    }

    fcb = snotify_add_watch(sctx,
                            /* TODO - it makes sense to have the same mask for passwd and files */ 0,
                            fn, id_ctx);
    if (fcb == NULL) {
        talloc_free(sctx);
        return NULL;
    }
    /* fcb is now owned by sctx */

    return sctx;
}

struct files_ctx *sf_init(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          const char *passwd_file,
                          const char *group_file,
                          struct files_id_ctx *id_ctx)
{
    struct files_ctx *fctx;

    fctx = talloc(mem_ctx, struct files_ctx);
    if (fctx == NULL) {
        return NULL;
    }

    fctx->ops = nss_files_open(fctx, NULL);
    if (fctx->ops == NULL) {
        talloc_free(fctx);
        return NULL;
    }

    fctx->pwd_watch = sf_setup_watch(fctx, ev, passwd_file,
                                     sf_passwd_cb, id_ctx);
    fctx->grp_watch = sf_setup_watch(fctx, ev, group_file,
                                     sf_group_cb, id_ctx);
    if (fctx->pwd_watch == NULL || fctx->grp_watch == NULL) {
        talloc_free(fctx);
        return NULL;
    }

    return fctx;
}
