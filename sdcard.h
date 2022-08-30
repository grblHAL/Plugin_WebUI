/*
  sdcard.h - An embedded CNC Controller with rs274/ngc (g-code) support

  Webserver backend - sdcard handling

  Part of grblHAL

  Copyright (c) 2020-2022 Terje Io

  Some parts of the code is based on test code by francoiscolas
  https://github.com/francoiscolas/multipart-parser/blob/master/tests.cpp

  Grbl is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  Grbl is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with Grbl.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __WEBUI_SDCARD_H__
#define __WEBUI_SDCARD_H__

#include "webui.h"

#include "../networking/httpd.h"
#include "../networking/http_upload.h"

const char *sdcard_handler (http_request_t *request);
const char *sdcard_upload_handler (http_request_t *request);
const char *sdcard_download_handler (http_request_t *request);

#endif // __WEBUI_SDCARD_H__
