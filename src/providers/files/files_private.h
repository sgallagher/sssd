/*
    SSSD

    Files provider declarations

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

#ifndef __FILES_PRIVATE_H_
#define __FILES_PRIVATE_H_

#include "config.h"

#include <talloc.h>
#include <errno.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include "providers/dp_backend.h"

struct files_id_ctx {
    struct be_ctx *be;
    struct files_ctx *fctx;
};

struct files_ctx *sf_init(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          const char *passwd_file,
                          const char *group_file,
                          struct files_id_ctx *id_ctx);

#endif /* __FILES_PRIVATE_H_ */
