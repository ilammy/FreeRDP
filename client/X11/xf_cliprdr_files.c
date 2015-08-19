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
#include <ftw.h>
#include <unistd.h>

#include "xf_cliprdr_files.h"

#define TAG CLIENT_TAG("x11.cliprdr")

#define CLIPRDR_TEMPDIR_PATTERN "/tmp/freerdp.cliprdr.XXXXXX"

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
