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

#ifndef __INOTIFY_H_
#define __INOTIFY_H_

#include <talloc.h>
#include <tevent.h>
#include <sys/inotify.h>

typedef int (*snotify_cb_fn)(const char *filename, void *pvt);

struct snotify_ctx *snotify_create(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   const char *filename,
                                   int burst_rate);

struct snotify_cb_ctx *snotify_add_watch(struct snotify_ctx *snctx,
                                         uint32_t mask,
                                         snotify_cb_fn fn,
                                         void *pvt);

#endif /*  __INOTIFY_H_ */
