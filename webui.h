/*
  webui/webui.h - An embedded CNC Controller with rs274/ngc (g-code) support

  WebUI backend for https://github.com/luc-github/ESP3D-webui

  Part of grblHAL

  Copyright (c) 2019-2025 Terje Io

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

#define COOKIEPREFIX "ESPSESSIONID="

typedef enum {
    WebUIAuth_None = 0,
    WebUIAuth_Guest,
    WebUIAuth_User,
    WebUIAuth_Admin
} webui_auth_level_t;

typedef char session_id_t[21];
typedef char user_id_t[17];

// implemented in server.c
char *webui_get_sys_path (void);
bool webui_maintenance_mode (void);
network_info_t *webui_get_server_info (void);
