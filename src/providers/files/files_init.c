/*
    SSSD

    files_init.c - Initialization of the files provider

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

#include "util/util.h"
#include "providers/dp_backend.h"
#include "providers/files/files_private.h"

static void files_shutdown(struct be_req *req);
static void files_get_account_info(struct be_req *breq);

struct bet_ops files_id_ops = {
    .handler = files_get_account_info,
    .finalize = files_shutdown,
    .check_online = NULL
};

int sssm_files_id_init(struct be_ctx *bectx,
                       struct bet_ops **ops,
                       void **pvt_data)
{
    struct files_id_ctx *ctx;
    int ret;
    const char *passwd_file = "/etc/passwd"; /* TODO - read from config file */
    const char *group_file = "/etc/group"; /* TODO - read from config file */

    ctx = talloc_zero(bectx, struct files_id_ctx);
    if (!ctx) {
        return ENOMEM;
    }
    ctx->be = bectx;

    ctx->fctx = sf_init(ctx, bectx->ev, passwd_file, group_file, ctx);
    if (ctx->fctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *ops = &files_id_ops;
    *pvt_data = ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}

static void files_get_account_info(struct be_req *breq)
{
    struct be_acct_req *ar;

    ar = talloc_get_type(be_req_get_data(breq), struct be_acct_req);

    switch (ar->entry_type & BE_REQ_TYPE_MASK) {
    case BE_REQ_USER:
        switch (ar->filter_type) {
        case BE_FILTER_ENUM:
        case BE_FILTER_NAME:
        case BE_FILTER_IDNUM:
            break;
        default:
            goto fail;
        }
        break;
    case BE_REQ_GROUP:
        switch (ar->filter_type) {
        case BE_FILTER_ENUM:
        case BE_FILTER_NAME:
        case BE_FILTER_IDNUM:
            break;
        default:
            goto fail;
        }
        break;
    case BE_REQ_INITGROUPS:
        switch (ar->filter_type) {
        case BE_FILTER_NAME:
            break;
        default:
            goto fail;
        }
        break;
    }

    /* All data is in fact returned from responder cache for now */

    return be_req_terminate(breq, DP_ERR_OK, EOK, NULL);

fail:
    return be_req_terminate(breq, DP_ERR_FATAL,
                            EINVAL, "Invalid request type");
}

static void files_shutdown(struct be_req *req)
{
    be_req_terminate(req, DP_ERR_OK, EOK, NULL);
}
