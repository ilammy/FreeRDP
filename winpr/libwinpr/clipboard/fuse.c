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

#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <winpr/clipboard.h>
#include <winpr/string.h>
#include <winpr/thread.h>
#include <winpr/wlog.h>

#include <fuse/fuse.h>

#include "clipboard.h"
#include "fuse.h"

#include "../log.h"
#define TAG WINPR_TAG("clipboard.fuse")

struct fuse_subsystem_context
{
	char* mount_point;
	struct fuse_chan* fuse_channel;
	struct fuse* fuse;
	HANDLE fuse_thread;
};

static const struct fuse_operations fuse_subsystem_ops = {
};

static DWORD fuse_thread(LPVOID lpThreadParameter)
{
	int ret = 0;
	struct fuse_subsystem_context* subsystem = lpThreadParameter;

	ret = fuse_loop(subsystem->fuse);

	WLog_DBG(TAG, "fuse_loop() exited with %d", ret);

	return NO_ERROR;
}

static void stop_fuse_thread(struct fuse_subsystem_context* subsystem)
{
	fuse_exit(subsystem->fuse);

	WaitForSingleObject(subsystem->fuse_thread, INFINITE);
	CloseHandle(subsystem->fuse_thread);

	subsystem->fuse_thread = 0;
}

static BOOL init_fuse(struct fuse_subsystem_context* subsystem)
{
	subsystem->fuse_channel = fuse_mount(subsystem->mount_point, NULL);
	if (!subsystem->fuse_channel)
		return FALSE;

	subsystem->fuse = fuse_new(subsystem->fuse_channel, NULL,
		&fuse_subsystem_ops, sizeof(fuse_subsystem_ops),
		subsystem);
	if (!subsystem->fuse)
		goto error_unmount_channel;

	subsystem->fuse_thread = CreateThread(NULL, 0, fuse_thread, subsystem,
		0, NULL);
	if (!subsystem->fuse_thread)
		goto error_destroy_fuse;

	return TRUE;

error_destroy_fuse:
	fuse_destroy(subsystem->fuse);
	subsystem->fuse = NULL;
error_unmount_channel:
	fuse_unmount(subsystem->mount_point, subsystem->fuse_channel);
	subsystem->fuse_channel = NULL;

	return FALSE;
}

static void free_fuse(struct fuse_subsystem_context* subsystem)
{
	stop_fuse_thread(subsystem);

	fuse_unmount(subsystem->mount_point, subsystem->fuse_channel);
	fuse_destroy(subsystem->fuse);

	subsystem->fuse_channel = NULL;
	subsystem->fuse = NULL;
}

static BOOL ensure_directory(const char* path)
{
	int err = 0;
	struct stat buf;

	errno = 0;

	if (mkdir(path, 0775) == 0)
		return TRUE;

	if (errno == EEXIST)
	{
		errno = 0;

		if (stat(path, &buf) == 0)
			return S_ISDIR(buf.st_mode);
	}

	err = errno;
	WLog_DBG(TAG, "failed to make directory %s: %s", path, strerror(err));
	return FALSE;
}

static void remove_directory(const char* path)
{
	int err = 0;

	errno = 0;

	if (rmdir(path) == 0)
		return;

	err = errno;
	WLog_DBG(TAG, "failed to remove directory %s: %s", path, strerror(err));
}

static BOOL ensure_mount_point_at(struct fuse_subsystem_context* subsystem,
		char* path)
{
	char* delimiter;

	if (path[0] == '\0')
		return FALSE;

	/* mkdir -p */
	for (delimiter = path + 1; *delimiter; delimiter++)
	{
		if (*delimiter == '/')
		{
			*delimiter = '\0';
			if (!ensure_directory(path))
				return FALSE;
			*delimiter = '/';
		}
	}
	if (!ensure_directory(path))
		return FALSE;

	subsystem->mount_point = _strdup(path);
	if (!subsystem->mount_point)
	{
		remove_directory(path);
		return FALSE;
	}

	WLog_DBG(TAG, "initialized FUSE mount point at %s", path);

	return TRUE;
}

static BOOL ensure_mount_point(struct fuse_subsystem_context* subsystem)
{
	char path[256];
	pid_t pid = getpid();
	uid_t uid = getuid();

	snprintf(path, sizeof(path), "/var/run/user/%u/winpr/clipboard-%d", uid, pid);
	if (ensure_mount_point_at(subsystem, path))
		return TRUE;

	snprintf(path, sizeof(path), "/tmp/winpr/%u/clipboard-%d", uid, pid);
	if (ensure_mount_point_at(subsystem, path))
		return TRUE;

	WLog_DBG(TAG, "failed to initialize FUSE mount point");
	return FALSE;
}

static void remove_mount_point(struct fuse_subsystem_context* subsystem)
{
	/*
	 * Despite the fact that we can create the whole directory chain for
	 * a path like "/var/run/user/XXXX/winpr/clipboard-YYYY", we remove
	 * only the terminating "clipboard-YYYY" directory because the parent
	 * directories may be currently in use by other processes.
	 */
	remove_directory(subsystem->mount_point);
	free(subsystem->mount_point);
	subsystem->mount_point = NULL;
}

static struct fuse_subsystem_context* make_subsystem_context(void)
{
	struct fuse_subsystem_context* subsystem = NULL;

	subsystem = calloc(1, sizeof(*subsystem));
	if (!subsystem)
		return NULL;

	if (!ensure_mount_point(subsystem))
		goto error_free_subsystem;

	if (!init_fuse(subsystem))
		goto error_remove_mount_point;

	return subsystem;

error_remove_mount_point:
	remove_mount_point(subsystem);
error_free_subsystem:
	free(subsystem);

	return NULL;
}

static void free_subsystem_context(void* context)
{
	struct fuse_subsystem_context* subsystem = context;

	if (subsystem)
	{
		free_fuse(subsystem);
		remove_mount_point(subsystem);

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
