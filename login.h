/*
  login.h - An embedded CNC Controller with rs274/ngc (g-code) support

  Webserver backend - login handling

  Part of grblHAL

  Copyright (c) 2022 Terje Io

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

#ifndef __WEBUI_LOGIN_H__
#define __WEBUI_LOGIN_H__

#include "../grbl/plugins.h"
#include "../networking/httpd.h"

#include "webui.h"

typedef enum
{
    Login_Parsing = 0,
    Login_GetAction,
    Login_GetUserName,
    Login_GetPassword,
    Login_GetNewPassword,
    Login_Failed,
    Login_Complete
} login_parse_state_t;

typedef enum
{
    LoginAction_None = 0,
    LoginAction_Disconnect,
    LoginAction_Submit,
} login_action_t;

typedef struct {
    login_parse_state_t state;
    char header_name[100];
    char header_value[50];
    login_action_t action;
    char action_param[20];
    char user[50];
    password_t password;
    password_t new_password;
    http_request_t *request;
} login_form_data_t;

void login_init (void);
#if WEBUI_AUTH_ENABLE
webui_auth_level_t get_auth_level (http_request_t *request);
const char *login_handler_get (http_request_t *request);
const char *login_handler_post (http_request_t *request);
uint32_t login_get_timeout_period (void);
#endif

#endif
