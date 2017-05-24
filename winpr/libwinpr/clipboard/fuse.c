/**
 * WinPR: Windows Portable Runtime
 * Clipboard Functions: libfuse remote file backend
 *
 * Copyright 2017 Alexei Lozovsky <a.lozovsky@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include <winpr/clipboard.h>
#include <winpr/wlog.h>

#include "clipboard.h"
#include "fuse.h"

#include "../log.h"
#define TAG WINPR_TAG("clipboard.fuse")

struct fuse_subsystem_context
{
};

static struct fuse_subsystem_context* make_subsystem_context(void)
{
	struct fuse_subsystem_context* subsystem = NULL;

	subsystem = calloc(1, sizeof(*subsystem));
	if (!subsystem)
		return NULL;

	return subsystem;
}

static void free_subsystem_context(void* context)
{
	struct fuse_subsystem_context* subsystem = context;

	if (subsystem)
	{
		free(subsystem);
	}
}

BOOL ClipboardInitFuseFileSubsystem(wClipboard* clipboard)
{
	if (!clipboard)
		return FALSE;

	clipboard->remoteFileSubsystem = make_subsystem_context();
	if (!clipboard->remoteFileSubsystem)
		return FALSE;

	clipboard->freeRemoteFileSubsystem = free_subsystem_context;

	return TRUE;
}
