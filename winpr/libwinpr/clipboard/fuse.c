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
#include <winpr/shell.h>
#include <winpr/string.h>
#include <winpr/thread.h>
#include <winpr/wlog.h>

#include <fuse/fuse.h>

#include "clipboard.h"
#include "fuse.h"

#include "../log.h"
#define TAG WINPR_TAG("clipboard.fuse")

struct fuse_file
{
	char* local_name;
	UINT32 index;

	BOOL is_directory;
	wArrayList* contents;
};

struct fuse_subsystem_context
{
	char* mount_point;
	struct fuse_chan* fuse_channel;
	struct fuse* fuse;
	HANDLE fuse_thread;
	struct fuse_file *root_directory;
};

static void free_fuse_file(void* the_file)
{
	struct fuse_file* file = the_file;

	if (!file)
		return;

	ArrayList_Free(file->contents);
	free(file->local_name);

	free(file);
}

static struct fuse_file* make_fuse_file(char* local_name, UINT32 index, BOOL is_directory)
{
	struct fuse_file* file = NULL;

	file = calloc(1, sizeof(*file));
	if (!file)
	{
		free(local_name);
		return NULL;
	}

	file->local_name = local_name;
	file->index = index;

	if (is_directory)
	{
		file->is_directory = TRUE;
		file->contents = ArrayList_New(FALSE);

		if (!file->contents)
			goto error;

		ArrayList_Object(file->contents)->fnObjectFree = free_fuse_file;
	}

	return file;

error:
	free(file->local_name);
	free(file);

	return NULL;
}

static size_t next_path_component(const char* path)
{
	return strcspn(path, "/");
}

static struct fuse_file* lookup_child_file(const char* name, wArrayList* children,
		size_t name_len, size_t prefix_len)
{
	int i;
	int count = ArrayList_Count(children);

	WLog_VRB(TAG, "lookup_child_file: looking for \"%s\"", name);

	for (i = 0; i < count; i++)
	{
		struct fuse_file* child = ArrayList_GetItem(children, i);
		const char *child_name = child->local_name + prefix_len;
		size_t child_name_len = next_path_component(child_name);

		WLog_VRB(TAG, "lookup_child_file: child_name=\"%s\"", child_name);

		if ((name_len == child_name_len) && (!strncmp(name, child_name, name_len)))
		{
			return child;
		}
	}

	WLog_VRB(TAG, "lookup_child_file: not found: \"%s\"", name);

	return NULL;
}

static int lookup_fuse_file(struct fuse_file* root, const char* name,
		struct fuse_file** file_out)
{
	struct fuse_file* file = root;

	/*
	 * FUSE filenames are always 'absolute' (start with a slash)
	 * relative to the filesystem mount point. Skip that slash.
	 */
	if (*name != '/')
	{
		WLog_WARN(TAG, "expected absolute FUSE filename: \"%s\"", name);
		return -EINVAL;
	}
	name++;

	while (*name)
	{
		size_t file_name_len = next_path_component(name);
		size_t dir_name_len = strlen(file->local_name);

		if (!file->is_directory)
		{
			WLog_VRB(TAG, "lookup_fuse_file: expected a directory: \"%s\"",
				file->local_name);
			return -ENOTDIR;
		}

		/*
		 * Include slash into the directory name length.
		 * Root directory is an exception as it has empty path.
		 */
		if (dir_name_len > 0)
			dir_name_len++;

		file = lookup_child_file(name, file->contents,
			file_name_len, dir_name_len);

		WLog_VRB(TAG, "lookup_fuse_file: name=\"%s\" next=\"%s\"",
			 name, file ? file->local_name : NULL);

		if (!file)
			return -ENOENT;

		/*
		 * Skip to the next path component, over the slash.
		 */
		name += file_name_len;
		if (*name == '/')
			name++;
	}

	if (file_out)
		*file_out = file;

	return 0;
}

static int lookup_fuse_file_cached(struct fuse_file* root, const char* name,
		struct fuse_file_info* info, struct fuse_file** file_out,
		BOOL require_directory)
{
	int err;
	struct fuse_file* file;

	if (info && info->fh)
	{
		if (file_out)
			*file_out = (struct fuse_file*) info->fh;
		return 0;
	}

	err = lookup_fuse_file(root, name, &file);
	if (err)
		return err;

	if (require_directory && !file->is_directory)
	{
		WLog_VRB(TAG, "lookup_fuse_file_cached: not a directory: \"%s\"", name);
		return -ENOTDIR;
	}

	if (info)
		info->fh = (uint64_t) file;
	if (file_out)
		*file_out = file;

	return 0;
}

static int fuse_getattr(const char* name, struct stat* statbuf)
{
	static const mode_t kFileMode = 0644 | S_IFREG;
	static const mode_t kDirMode = 0755 | S_IFDIR;

	int err;
	struct fuse_file *file;
	struct fuse_subsystem_context* subsystem = fuse_get_context()->private_data;

	WLog_VRB(TAG, "fuse_getattr: \"%s\"", name);

	err = lookup_fuse_file(subsystem->root_directory, name, &file);
	if (err)
		return err;

	statbuf->st_ino = file->index;
	statbuf->st_mode = file->is_directory ? kDirMode : kFileMode;
	statbuf->st_size = 0; /* TODO: fill in the size if known */

	return 0;
}

static int fuse_opendir(const char* name, struct fuse_file_info* info)
{
	struct fuse_subsystem_context* subsystem = fuse_get_context()->private_data;

	WLog_VRB(TAG, "fuse_opendir: \"%s\"", name);

	return lookup_fuse_file_cached(subsystem->root_directory, name, info,
		NULL, TRUE);
}

static int fill_readdir_buffer(struct fuse_file* dir, void* buffer, fuse_fill_dir_t fdt)
{
	int i;
	int count = ArrayList_Count(dir->contents);
	size_t dir_name_len = strlen(dir->local_name);

	for (i = 0; i < count; i++)
	{
		struct fuse_file* file = ArrayList_GetItem(dir->contents, i);
		const char* file_name = file->local_name + dir_name_len + 1;

		WLog_VRB(TAG, "fill_readdir_buffer: %s > %s", dir->local_name, file_name);

		/*
		 * TODO: fill statbuf to avoid lookups
		 */

		if (fdt(buffer, file_name, NULL, 0))
			return -ENOMEM;
	}

	return 0;
}

static int fuse_readdir(const char* name, void* buffer, fuse_fill_dir_t fdt,
		off_t offset, struct fuse_file_info* info)
{
	int err;
	struct fuse_file* dir;
	struct fuse_subsystem_context* subsystem = fuse_get_context()->private_data;

	WLog_VRB(TAG, "fuse_readdir: \"%s\"", name);

	err = lookup_fuse_file_cached(subsystem->root_directory, name, info,
		&dir, TRUE);
	if (err)
		return err;

	return fill_readdir_buffer(dir, buffer, fdt);
}

static int fuse_releasedir(const char* name, struct fuse_file_info* info)
{
	WLog_VRB(TAG, "fuse_releasedir: \"%s\"", name);

	info->fh = 0;

	return 0;
}

static const struct fuse_operations fuse_subsystem_ops = {
	.getattr = fuse_getattr,
	.opendir = fuse_opendir,
	.readdir = fuse_readdir,
	.releasedir = fuse_releasedir,
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

	/*
	 * This is a hack. fuse_loop() blocks for indefinite amount of time
	 * until some FUSE event arrives for the filesystem, which will never
	 * happen as we're shutting down and do not provide clipboard anymore.
	 *
	 * fuse_exit() does *not* interrupt fuse_loop() immediately, only
	 * after it's unblocked. Thus we have to disgracefully kill the thread
	 * to make it stop. This could be handled better with signals (which
	 * can interrupt system calls), but that's hard to do cleanly.
	 */
	TerminateThread(subsystem->fuse_thread, 0);

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

	subsystem->root_directory = make_fuse_file(_strdup(""), -1, TRUE);

	if (!subsystem->root_directory)
		goto error_free_fuse;

	return subsystem;

error_free_fuse:
	free_fuse(subsystem);
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
		free_fuse_file(subsystem->root_directory);

		free(subsystem);
	}
}

static char* remote_to_local_filename(const WCHAR* remote_filename)
{
	char* c;
	char* local_filename = NULL;

	if (!ConvertFromUnicode(CP_UTF8, 0, remote_filename, -1, &local_filename, 0, NULL, FALSE)) {
		WLog_WARN(TAG, "Unicode conversion failed");
		return NULL;
	}

	for (c = local_filename; *c; c++)
		if (*c == '\\')
			*c = '/';

	return local_filename;
}

static struct fuse_file* convert_filedescriptor_to_fuse_file(const FILEDESCRIPTOR *descriptor,
		UINT32 index)
{
	char* local_filename = NULL;
	struct fuse_file* file = NULL;

	local_filename = remote_to_local_filename(descriptor->cFileName);
	if (!local_filename)
		return NULL;

	file = make_fuse_file(local_filename, index,
		descriptor->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);

	/*
	 * We ignore other file attributes. Modification time makes little
	 * sense for files pasted from remote machine at the current moment.
	 * File size is not set most of the time in FILEDESCRIPTOR structs
	 * so we will explicitly request it later.
	 */

	return file;
}

static struct fuse_file** convert_filedescriptors_to_fuse_files(
		const FILEDESCRIPTOR* descriptors, UINT32 count)
{
	UINT32 i;
	struct fuse_file** files = NULL;

	files = calloc(count, sizeof(*files));
	if (!files)
		return FALSE;

	for (i = 0; i < count; i++)
	{
		files[i] = convert_filedescriptor_to_fuse_file(&descriptors[i], i);
		if (!files[i])
			goto error;
	}

	return files;

error:
	for (i = 0; i < count; i++)
		free_fuse_file(files[i]);

	free(files);

	return NULL;
}

static int compare_files_by_name(const void* the_lhs, const void* the_rhs)
{
	const struct fuse_file* lhs = *((const struct fuse_file**) the_lhs);
	const struct fuse_file* rhs = *((const struct fuse_file**) the_rhs);

	return strcmp(lhs->local_name, rhs->local_name);
}

static void sort_fuse_files_by_name(struct fuse_file** files, UINT32 count)
{
	qsort(files, count, sizeof(*files), compare_files_by_name);
}

static BOOL contains(size_t len, const char* directory, const char* file)
{
	/* strncmp() first, so that we're sure that strlen(file) >= len */
	return (strncmp(directory, file, len) == 0) && (file[len] == '/');
}

static UINT32 push_files_rec(struct fuse_file** all_files, UINT32 index, UINT32 count,
		wArrayList* directory, UINT32 level, BOOL* success)
{
	UINT32 i;
	size_t prefix_length = 0;

	WLog_VRB(TAG, "push_files: [%u.%u] (%c) %s", level, index,
		all_files[index]->is_directory ? 'd' : '-',
		all_files[index]->local_name);

	if (ArrayList_Add(directory, all_files[index]) < 0)
		*success = FALSE;

	if (!all_files[index]->is_directory)
		return index + 1;

	prefix_length = strlen(all_files[index]->local_name);

	for (i = index + 1; i < count;)
	{
		if (!contains(prefix_length, all_files[index]->local_name, all_files[i]->local_name))
			break;

		i = push_files_rec(all_files, i, count, all_files[index]->contents, level + 1, success);
	}

	WLog_VRB(TAG, "push_files: [%u.%u] done", level, i);

	return i;
}

static BOOL push_files(struct fuse_file** all_files, UINT32 count, wArrayList* remote_files)
{
	UINT32 i;
	BOOL success = TRUE;

	ArrayList_Clear(remote_files);

	WLog_VRB(TAG, "push_files: will process %d files", count);

	for (i = 0; i < count;)
	{
		i = push_files_rec(all_files, i, count, remote_files, 0, &success);
	}

	WLog_VRB(TAG, "push_files: done");

	if (!success)
		WLog_ERR(TAG, "failed to process all files");

	return success;
}

static BOOL process_filedescriptors(const FILEDESCRIPTOR* descriptors, UINT32 count,
		wArrayList* remote_files)
{
	struct fuse_file** all_files = NULL;

	all_files = convert_filedescriptors_to_fuse_files(descriptors, count);
	if (!all_files)
		return FALSE;

	/*
	 * We need to convert a flat list of files with relative names back
	 * into hierachical directory structure. First we sort the files to
	 * get them into topological order. Fortunately, lexical sort is
	 * also a topological one for file names. After that we carefully
	 * restore the directory structure by tracking file name prefixes.
	 */

	sort_fuse_files_by_name(all_files, count);

	if (!push_files(all_files, count, remote_files))
		goto error;

	free(all_files);
	return TRUE;

error:
	ArrayList_Clear(remote_files);
	free(all_files);
	return FALSE;
}

static BOOL Stream_Append(wStream* s, const char* str)
{
	size_t length = strlen(str);

	if (!Stream_EnsureRemainingCapacity(s, length))
		return FALSE;

	Stream_Write(s, str, length);

	return TRUE;
}

static BOOL should_percent_encode(BYTE c)
{
	/*
	 * See RFC 3986 on what should be encoded. We should leave unreserved
	 * characters as is and do not escape the slashes because they really
	 * delimit URL paths. Everything else must be percent-encoded.
	 */
	if (('A' <= c) && (c <= 'Z'))
		return FALSE;
	if (('a' <= c) && (c <= 'z'))
		return FALSE;
	if (('0' <= c) && (c <= '9'))
		return FALSE;
	if ((c == '-') || (c == '_') || (c == '.') || (c == '~') || (c == '/'))
		return FALSE;

	return TRUE;
}

static BYTE as_hex(BYTE n)
{
	static const char* nibbles = "0123456789ABCDEF";

	return (n < 16) ? nibbles[n] : 'X';
}

static BOOL Stream_Append_PercentEncoded(wStream* s, const char* str)
{
	const char *c;
	size_t length = strlen(str);

	/* Percent-encoding inflates number of characters maximum by three. */
	if (!Stream_EnsureRemainingCapacity(s, 3 * length))
		return FALSE;

	for (c = str; *c; c++) {
		BYTE b = *c;
		if (should_percent_encode(b)) {
			Stream_Write_UINT8(s, '%');
			Stream_Write_UINT8(s, as_hex((b >> 4) & 0x0F));
			Stream_Write_UINT8(s, as_hex((b >> 0) & 0x0F));
		} else {
			Stream_Write_UINT8(s, b);
		}
	}

	return TRUE;
}

static BOOL append_file_to_uri_list(const char* mount_point, struct fuse_file* file, wStream* s)
{
	if (!Stream_Append(s, "file://"))
		return FALSE;

	if (!Stream_Append_PercentEncoded(s, mount_point))
		return FALSE;

	if (!Stream_Append(s, "/"))
		return FALSE;

	if (!Stream_Append_PercentEncoded(s, file->local_name))
		return FALSE;

	if (!Stream_Append(s, "\n"))
		return FALSE;

	return TRUE;
}

static BOOL do_convert_remote_file_list_to_uri_list(const char* mount_point,
		wArrayList* remote_files, wStream* s)
{
	int i;
	int count;

	/*
	 * We have no idea whether the files are copied or cut on the remote
	 * side, so allow pasting them multiple times just in case.
	 */
	if (!Stream_Append(s, "copy\n"))
		return FALSE;

	count = ArrayList_Count(remote_files);

	for (i = 0; i < count; i++)
	{
		struct fuse_file* file = ArrayList_GetItem(remote_files, i);

		if (!append_file_to_uri_list(mount_point, file, s))
			return FALSE;
	}

	/*
	 * Trim the last newline. Some applications expect files to be
	 * delimited by newlines and are offended by 'empty' file names.
	 */
	Stream_Rewind(s, 1);

	return TRUE;
}

static char* convert_remote_file_list_to_uri_list(const char* mount_point,
		wArrayList* remote_files, UINT32* length)
{
	wStream* s;
	char* buffer;

	/* TODO: tweak the initial size after measurements */
	s = Stream_New(NULL, 4096);
	if (!s)
		goto error;

	if (!do_convert_remote_file_list_to_uri_list(mount_point, remote_files, s))
		goto error_free_stream;

	Stream_SealLength(s);

	buffer = (char*) Stream_Buffer(s);
	*length = (UINT32) Stream_Length(s);

	Stream_Free(s, FALSE);

	return buffer;

error_free_stream:
	Stream_Free(s, TRUE);
error:
	*length = 0;
	return NULL;
}

static void* convert_filedescriptors_to_uri_list(wClipboard* clipboard, UINT32 formatId,
		const void* data, UINT32* pSize)
{
	struct fuse_subsystem_context* context = clipboard->remoteFileSubsystem;
	char* uri_list = NULL;

	if (!clipboard || !data || !pSize)
		return NULL;

	if (formatId != ClipboardGetFormatId(clipboard, "FileGroupDescriptorW"))
		return NULL;

	if (*pSize % sizeof(FILEDESCRIPTOR) != 0)
		return NULL;

	if (!process_filedescriptors((const FILEDESCRIPTOR*) data, *pSize / sizeof(FILEDESCRIPTOR),
			context->root_directory->contents))
		return NULL;

	uri_list = convert_remote_file_list_to_uri_list(context->mount_point,
			context->root_directory->contents, pSize);
	if (!uri_list)
		return NULL;

	return uri_list;
}

static BOOL register_file_formats_and_synthesizers(wClipboard* clipboard)
{
	UINT32 file_group_format_id;
	UINT32 local_file_format_id;

	file_group_format_id = ClipboardRegisterFormat(clipboard, "FileGroupDescriptorW");
	local_file_format_id = ClipboardRegisterFormat(clipboard, "x-special/gnome-copied-files");
	if (!file_group_format_id || !local_file_format_id)
		return FALSE;

	if (!ClipboardRegisterSynthesizer(clipboard,
			file_group_format_id, local_file_format_id,
			convert_filedescriptors_to_uri_list))
		return FALSE;

	return TRUE;
}

BOOL ClipboardInitFuseFileSubsystem(wClipboard* clipboard)
{
	if (!clipboard)
		return FALSE;

	if (!register_file_formats_and_synthesizers(clipboard))
		return FALSE;

	clipboard->remoteFileSubsystem = make_subsystem_context();
	if (!clipboard->remoteFileSubsystem)
		return FALSE;

	clipboard->freeRemoteFileSubsystem = free_subsystem_context;

	return TRUE;
}
