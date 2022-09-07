/*
  webui/commands_v3.h - An embedded CNC Controller with rs274/ngc (g-code) support

  WebUI backend for https://github.com/luc-github/ESP3D-webui

  Part of grblHAL

  Copyright (c) 2019-2022 Terje Io

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

#ifndef __WEBUI_COMMANDS3_H__
#define __WEBUI_COMMANDS3_H__

#include "webui.h"

#include "grbl/grbl.h"

status_code_t webui_v3_command_handler (uint32_t command, uint_fast16_t argc, char **argv, webui_auth_level_t auth_level, vfs_file_t *file);
status_code_t webui_v3_get_system_status (uint_fast16_t command_id, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);

#endif
