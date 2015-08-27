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

#ifndef __XF_CLIPRDR_FILES_H
#define __XF_CLIPRDR_FILES_H

#include "xf_cliprdr.h"
#include "xfreerdp.h"

#include <winpr/collections.h>

typedef struct file_information fileInfo;

struct file_information
{
	/* Remote */
	int listIndex;
	BOOL isDirectory;
	char* remoteName;
	BOOL haveSize;
	UINT64 size;

	/* Local */
	char* localName;
};

char* xf_cliprdr_initialize_temporary_directory(void);
void xf_cliprdr_remove_temporary_directory(const char* dir);

BOOL xf_cliprdr_initialize_transfer(const char* tempdir, wArrayList* files);

wArrayList* xf_cliprdr_parse_file_descriptor_list(BYTE* data, UINT32 size);

UINT32 xf_cliprdr_append_file_data(fileInfo* file, BYTE* data, UINT32 len);

BYTE* xf_cliprdr_serialize_file_list(wArrayList* files, int* size);

#endif /* __XF_CLIPRDR_FILES_H */
