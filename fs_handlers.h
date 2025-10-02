/*
  fs_handlers.h - An embedded CNC Controller with rs274/ngc (g-code) support

  WebUI backend - file handling

  Part of grblHAL

  Copyright (c) 2020-2024 Terje Io

  Some parts of the code is based on test code by francoiscolas
  https://github.com/francoiscolas/multipart-parser/blob/master/tests.cpp

  grblHAL is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  grblHAL is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with grblHAL. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "grbl/stream_json.h"

vfs_drive_t *fs_get_root_drive (void);
vfs_drive_t *fs_get_sd_drive (void);
vfs_drive_t *fs_get_flash_drive (bool add_hidden);
const char *fs_action_handler (http_request_t *request, vfs_drive_t *drive);
const char *fs_download_handler (http_request_t *request, vfs_drive_t *drive);
const char *fs_upload_handler (http_request_t *request, vfs_drive_t *drive);
bool fs_ls (json_out_t *root, char *path, char *status, vfs_drive_t *drive);
