/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * X11 Clipboard Redirection: File Clipping
 *
 * Copyright 2015 Alexei Lozovsky <a.lozovsky@gmail.com>
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

#define _XOPEN_SOURCE 700

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "xf_cliprdr_files.h"

#define TAG CLIENT_TAG("x11.cliprdr")

#define CLIPRDR_TEMPDIR_PATTERN "/tmp/freerdp.cliprdr.XXXXXX"
#define CLIPRDR_TRANFSER_PATTERN "transfer.XXXXXX"

#define DEFAULT_DIR_PERMISSIONS  0755
#define DEFAULT_FILE_PERMISSIONS 0644

/*
 *  Utilities
 */

static char* concat_file_path(const char* strA, const char* strB)
{
	char* buffer;
	size_t lenA;
	size_t lenS;
	size_t lenB;

	if (!strA || !strB)
		return NULL;

	lenA = strlen(strA);
	lenS = strlen("/");
	lenB = strlen(strB);

	buffer = malloc(lenA + lenS + lenB + 1);
	if (!buffer)
		return NULL;

	memcpy(&buffer[0], strA, lenA);
	memcpy(&buffer[lenA], "/", lenS);
	memcpy(&buffer[lenA + lenS], strB, lenB);
	buffer[lenA + lenS + lenB] = '\0';

	return buffer;
}

/*
 *  Transfer temporary directory
 */

char* xf_cliprdr_initialize_temporary_directory(void)
{
	int err = 0;
	char* tempdir = NULL;

	errno = 0;

	tempdir = _strdup(CLIPRDR_TEMPDIR_PATTERN);
	if (!tempdir)
		goto error;

	if (!mkdtemp(tempdir))
		goto error;

	return tempdir;

error:
	err = err ? err : errno;
	WLog_ERR(TAG, "failed to create temporary directory '%s': %d %s", tempdir, err, strerror(err));
	return NULL;
}

static int xf_cliprdr_clear_tempdir(const char* filename, const struct stat* status, int filetype, struct FTW* info)
{
	int err = 0;

	switch (filetype)
	{
	case FTW_F:
		if (unlink(filename) < 0)
		{
			err = errno;
		}
		break;

	case FTW_DP:
		if (rmdir(filename) < 0)
		{
			err = errno;
		}
		break;

	case FTW_DNR:
		err = EACCES;
		break;

	case FTW_NS:
	case FTW_SLN:
		err = ENOENT;
		break;

	default:
		err = EINVAL;
		break;
	}

	if (err)
		WLog_WARN(TAG, "failed to remove temporary '%s': %d %s", filename, err, strerror(err));

	/* Go on regardless of errors, try to remove as many files as possible */
	return 0;
}

void xf_cliprdr_remove_temporary_directory(const char* dir)
{
	int err = 0;

	if (!dir)
		return;

	errno = 0;

	if (nftw(dir, xf_cliprdr_clear_tempdir, 64, FTW_DEPTH) < 0)
	{
		err = errno;
	}

	if (err)
		WLog_ERR(TAG, "failed to remove temporary directory '%s': %d %s", dir, err, strerror(err));
}

static char* xf_cliprdr_create_transfer_directory(const char* tempdir)
{
	int err = 0;
	char* buffer = NULL;

	errno = 0;

	buffer = concat_file_path(tempdir, CLIPRDR_TRANFSER_PATTERN);
	if (!buffer)
		goto error;

	if (!mkdtemp(buffer))
		goto error;

	return buffer;

error:
	err = err ? err: errno;
	WLog_ERR(TAG, "failed to create transfer directory '%s' in '%s': %d %s", buffer, tempdir, err, strerror(err));
	free(buffer);
	return NULL;
}

static BOOL xf_cliprdr_initialize_transfer_directory(const char* tempdir, wArrayList* files)
{
	int i;
	int err = 0;
	int fileCount;
	char* filename = NULL;

	fileCount = ArrayList_Count(files);

	for (i = 0; i < fileCount; i++)
	{
		fileInfo* file = (fileInfo*) ArrayList_GetItem(files, i);

		if (!file->remoteName)
			continue;

		errno = 0;

		filename = concat_file_path(tempdir, file->remoteName);
		if (!filename)
			goto error;

		if (file->isDirectory)
		{
			if (mkdir(filename, DEFAULT_DIR_PERMISSIONS) < 0)
				goto error;
		}
		else
		{
			if (creat(filename, DEFAULT_FILE_PERMISSIONS) < 0)
				goto error;
		}

		free(file->localName);
		file->localName = filename;
	}

	return TRUE;

error:
	err = err ? err : errno;
	WLog_ERR(TAG, "failed to initialize transfer for '%s': %d %s", filename, err, strerror(err));
	free(filename);
	return FALSE;
}

BOOL xf_cliprdr_initialize_transfer(const char* tempdir, wArrayList* files)
{
	BOOL success = FALSE;
	char* transfer_directory = NULL;

	if (!tempdir || !files)
		return FALSE;

	transfer_directory = xf_cliprdr_create_transfer_directory(tempdir);
	if (!transfer_directory)
		return FALSE;

	success = xf_cliprdr_initialize_transfer_directory(transfer_directory, files);
	free(transfer_directory);
	return success;
}

/*
 *  FILE_DESCRIPTOR processing
 */

static void xf_cliprdr_windows_to_unix(char* str)
{
	if (!str)
		return;

	for (; *str; str++)
	{
		if (*str == '\\')
			*str = '/';
	}
}

static void xf_cliprdr_free_file_information(void* ptr)
{
	fileInfo* file = (fileInfo*) ptr;

	if (file)
	{
		free(file->remoteName);
		free(file);
	}
}

static int xf_cliprdr_compare_by_name(void* ptrA, void* ptrB)
{
	fileInfo* fileA = (fileInfo*) ptrA;
	fileInfo* fileB = (fileInfo*) ptrB;

	if (!fileA->remoteName || !fileB->remoteName)
		return 0; /* Should never happen, but whatever... */

	return strcmp(fileA->remoteName, fileB->remoteName);
}

static fileInfo* xf_cliprdr_convert_file_information(const CLIPRDR_FILEDESCRIPTOR* fileDescriptor)
{
	fileInfo* file = (fileInfo*) calloc(1, sizeof(fileInfo));
	if (!file)
		goto error;

	if (fileDescriptor->flags & FD_ATTRIBUTES)
	{
		if (fileDescriptor->fileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			file->isDirectory = TRUE;
		}
	}

	if (fileDescriptor->flags & FD_FILESIZE)
	{
		file->haveSize = TRUE;
		file->size = fileDescriptor->fileSizeHigh;
		file->size <<= 32;
		file->size += fileDescriptor->fileSizeLow;
	}

	if (ConvertFromUnicode(CP_UTF8, 0, (LPCWSTR) fileDescriptor->fileName, -1, &file->remoteName, 0, 0, FALSE) <= 0)
		goto error;

	xf_cliprdr_windows_to_unix(file->remoteName);

	return file;

error:
	xf_cliprdr_free_file_information(file);
	return NULL;
}

wArrayList* xf_cliprdr_parse_file_descriptor_list(BYTE* data, UINT32 size)
{
	UINT32 i;
	UINT32 cItems = 0;
	wStream* s = NULL;
	wArrayList* result = NULL;

	result = ArrayList_New(FALSE);
	if (!result)
		goto error;

	result->object.fnObjectFree = xf_cliprdr_free_file_information;

	s = Stream_New(data, size);
	if (!s)
		goto error;

	if (Stream_GetRemainingLength(s) < 4)
		goto error;

	Stream_Read_UINT32(s, cItems); /* cItems (4 bytes) */

	for (i = 0; i < cItems; i++)
	{
		fileInfo* file;
		CLIPRDR_FILEDESCRIPTOR fileDescriptor;

		if (Stream_GetRemainingLength(s) < 592)
			goto error;

		Stream_Read_UINT32(s, fileDescriptor.flags); /* flags (4 bytes) */
		Stream_Seek(s, 32); /* reserved1 (32 bytes) */
		Stream_Read_UINT32(s, fileDescriptor.fileAttributes); /* fileAttributes (4 bytes) */
		Stream_Seek(s, 16); /* reserved2 (16 bytes) */
		Stream_Read_UINT64(s, fileDescriptor.lastWriteTime); /* lastWriteTime (8 bytes) */
		Stream_Read_UINT32(s, fileDescriptor.fileSizeHigh); /* fileSizeHigh (4 bytes) */
		Stream_Read_UINT32(s, fileDescriptor.fileSizeLow); /* fileSizeLow (4 bytes) */
		Stream_Read(s, fileDescriptor.fileName, sizeof(fileDescriptor.fileName)); /* fileName (520 bytes) */

		file = xf_cliprdr_convert_file_information(&fileDescriptor);
		if (!file)
			goto error;

		file->listIndex = i;

		if (ArrayList_Add(result, (void*) file) < 0)
			goto error;
	}

	Stream_Free(s, FALSE);

	/* We will need the file list to be topologically sorted to recreate
	 * directory structure in a straightforward linear way. In fact, the
	 * server seems to always send correctly sorted CLIPRDR_FILELIST to us,
	 * but this is not guaranteed by the spec so we do a sort just in case.
	 * Lexicographical order is a topological order for file names. */
	ArrayList_SortWith(result, xf_cliprdr_compare_by_name);

	return result;

error:
	Stream_Free(s, FALSE);
	ArrayList_Free(result);
	return NULL;
}
