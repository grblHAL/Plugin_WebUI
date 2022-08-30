/*
  login.c - An embedded CNC Controller with rs274/ngc (g-code) support

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

#ifdef ARDUINO
#include "../driver.h"
#else
#include "driver.h"
#endif

#if WEBUI_ENABLE && WEBUI_AUTH_ENABLE

#include <stdio.h>
#include <string.h>
#include <stdio.h>

#include "grbl/vfs.h"
#include "grbl/nvs_buffer.h"

#include "../networking/cJSON.h"
#include "../networking/multipartparser.h"
#include "../networking/utils.h"
#include "../networking/strutils.h"

#include "./login.h"

typedef struct {
    password_t admin_password;
    password_t user_password;
} webui_settings_t;

typedef struct webui_auth {
    webui_auth_level_t level;
    ip_addr_t ip;
    user_id_t user_id;
    session_id_t session_id;
    uint32_t last_access;
    struct webui_auth *next;
} webui_auth_t;

static webui_auth_t *sessions = NULL;
static webui_settings_t webui;
static nvs_address_t nvs_address;
static void webui_settings_restore (void);
static void webui_settings_load (void);

static struct multipartparser parser;
static struct multipartparser_callbacks *login_callbacks = NULL;

static session_id_t *create_session_id (ip_addr_t ip, uint16_t port)
{
    static session_id_t session_id;

    uint32_t addr;

    memcpy(&addr, &ip, sizeof(uint32_t));

    if(sprintf(session_id, "%08X%04X%08X", addr, port, hal.get_elapsed_ticks()) != 20)
        memset(session_id, 0, sizeof(session_id_t));

    return &session_id;
}

static session_id_t *get_session_id (http_request_t *req, session_id_t *session_id)
{
    char *cookie = NULL, *token = NULL, *end = NULL;;
    int len = http_get_header_value_len(req, "Cookie");

    if(len > 0 && (cookie = malloc(len + 1))) {

        http_get_header_value(req, "Cookie", cookie, len + 1);

        if((token = strstr(cookie, COOKIEPREFIX))) {
            token += strlen(COOKIEPREFIX);
            if((end = strchr(token, ';')))
                *end = '\0';
            if(strlen(token) == sizeof(session_id_t) - 1)
                strcpy((char *)session_id, token);
            else
                token = NULL;
        }

        free(cookie);
    }

    return token ? session_id : NULL;
}

static bool unlink_session (http_request_t *req)
{
    bool ok = false;
    session_id_t session_id;

    if(get_session_id(req, &session_id)) {

        webui_auth_t *current = sessions, *previous = NULL;

        while(current) {

            if(memcmp(session_id, current->session_id, sizeof(session_id_t)) == 0) {
                ok = true;
                if(current == sessions) {
                    sessions = current->next;
                    free(current);
                    current = NULL;
                } else {
                    previous->next = current->next;
                    free(current);
                    current = NULL;
                }
            } else {
                previous = current;
                current = current->next;
            }
        }
    }

    return ok;
}

static char *authleveltostr (webui_auth_level_t level)
{
    return level == WebUIAuth_None ? "???" : level == WebUIAuth_Guest ? "guest" : level == WebUIAuth_User ? "user" : "admin";
}

static const char *login (login_form_data_t *login)
{
    bool ok = true;
    char msg[40] = "Ok", cookie[64];
    uint32_t status = 200;
    webui_auth_level_t auth_level = WebUIAuth_None;
    cJSON *root;

    switch(login->action) {

        case LoginAction_None:
            status = 500;
            strcpy(msg, "Error: Missing data");
            break;

        case LoginAction_Disconnect:
            unlink_session(login->request);
            auth_level = WebUIAuth_Guest;
            http_set_response_header(login->request, "Set-Cookie", strcat(strcpy(cookie, COOKIEPREFIX), "; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT"));
            status = 401;
            strcpy(msg, "disconnected");
            break;

        case LoginAction_Submit:
            if(*login->new_password) {

               strcpy(login->user, authleveltostr((auth_level = get_auth_level(login->request))));

               // TODO: validation against original password needed?

               if(*login->user && is_valid_password(login->new_password)) {

                   switch(strlookup(login->user, "user,admin", ',')) {

                       case 0:
                           if(settings_store_setting(Setting_UserPassword, login->new_password) != Status_OK) {
                               status = 401;
                               strcpy(msg, "Error: Cannot apply changes");
                           }
                           break;

                       case 1:
                           if(settings_store_setting(Setting_AdminPassword, login->new_password) != Status_OK) {
                               status = 401;
                               strcpy(msg, "Error: Cannot apply changes");
                           }
                           break;

                       default:
                           status = 401;
                           strcpy(msg, "Wrong authentication!");
                           break;
                   }
               } else {
                   status = 500;
                   strcpy(msg, "Error: Incorrect password");
               }

           } else if(*login->user) {

                auth_level = WebUIAuth_Guest;

                switch(strlookup(login->user, "user,admin", ',')) {

                    case 0:
                        if(strcmp(login->password, webui.user_password)) {
                            status = 401;
                            strcpy(msg, "Error: Incorrect password");
                        } else
                            auth_level = WebUIAuth_User;
                        break;

                    case 1:
                        if(strcmp(login->password, webui.admin_password)) {
                            status = 401;
                            strcpy(msg, "Error: Incorrect password");
                        } else
                            auth_level = WebUIAuth_Admin;
                        break;

                    default:
                        status = 401;
                        strcpy(msg, "Error: Unknown user");
                        break;
                }
            } else {
                status = 500;
                strcpy(msg, "Error: Missing data");
            }
            break;

        default:
            break;
    }

    if(status != 200) {
        char paranoia[50];
        sprintf(paranoia, "%d %s", (int)status, msg);
        http_set_response_status(login->request, paranoia);
    }

    http_set_response_header(login->request, "Cache-Control", "no-cache");

    webui_auth_level_t current_level = get_auth_level(login->request);

    if(auth_level != current_level) {

        unlink_session(login->request);

        if(auth_level >= WebUIAuth_User) {

            webui_auth_t *session;

            if((session = malloc(sizeof(webui_auth_t)))) {
                memset(session, 0, sizeof(webui_auth_t));

                ip_addr_t ip = http_get_remote_ip(login->request);
                memcpy(&session->ip, &ip, sizeof(ip_addr_t));
                memcpy(&session->session_id, create_session_id(session->ip, http_get_remote_port(login->request)), sizeof(session_id_t));

                session->level = auth_level;
                strcpy(session->user_id, login->user);
                session->last_access = hal.get_elapsed_ticks();
                session->next = sessions;
                sessions = session;
            }

            http_set_response_header(login->request, "Set-Cookie", strcat(strcat(strcpy(cookie, COOKIEPREFIX), session->session_id), "; path=/; SameSite=Strict"));
        }
    }

    if((root = cJSON_CreateObject())) {

        ok = cJSON_AddStringToObject(root, "status", msg) != NULL;
        ok &= !!cJSON_AddStringToObject(root, "authentication_lvl", authleveltostr(auth_level));

        if(ok) {
            char *resp = cJSON_PrintUnformatted(root);
            vfs_file_t *file = vfs_open("/stream/data.json", "w");
            hal.stream.write(resp);
            vfs_close(file);

            free(resp);
        }

        if(root)
            cJSON_Delete(root);
    }

    return ok ? "/stream/data.json" : NULL;
}

static const setting_detail_t webui_settings[] = {
    { Setting_AdminPassword, Group_General, "Admin Password", NULL, Format_Password, "x(32)", NULL, "32", Setting_NonCore, &webui.admin_password, NULL, NULL },
    { Setting_UserPassword, Group_General, "User Password", NULL, Format_Password, "x(32)", NULL, "32", Setting_NonCore, &webui.user_password, NULL, NULL },
};

static void webui_settings_save (void)
{
    hal.nvs.memcpy_to_nvs(nvs_address, (uint8_t *)&webui, sizeof(webui_settings_t), true);
}

static setting_details_t details = {
//    .groups = webui_groups,
//    .n_groups = sizeof(webui_groups) / sizeof(setting_group_detail_t),
    .settings = webui_settings,
    .n_settings = sizeof(webui_settings) / sizeof(setting_detail_t),
#ifndef NO_SETTINGS_DESCRIPTIONS
//    .descriptions = ethernet_settings_descr,
//    .n_descriptions = sizeof(ethernet_settings_descr) / sizeof(setting_descr_t),
#endif
    .save = webui_settings_save,
    .load = webui_settings_load,
    .restore = webui_settings_restore
};

static void webui_settings_restore (void)
{
    memset(&webui, 0, sizeof(webui_settings_t));

    hal.nvs.memcpy_to_nvs(nvs_address, (uint8_t *)&webui, sizeof(webui_settings_t), true);
}

static void webui_settings_load (void)
{
    if(hal.nvs.memcpy_from_nvs((uint8_t *)&webui, nvs_address, sizeof(webui_settings_t), true) != NVS_TransferResult_OK)
        webui_settings_restore();
}

static void cleanup (void *form)
{
    if(form)
        free(form);
}

static int on_body_begin (struct multipartparser *parser)
{
    return 0;
}

static int on_part_begin (struct multipartparser *parser)
{
    login_form_data_t *form = (login_form_data_t *)parser->data;

    *form->header_name = '\0';
    *form->header_value = '\0';

    return 0;
}

static void on_header_done (struct multipartparser *parser)
{
    login_form_data_t *form = (login_form_data_t *)parser->data;

    if(*form->header_value) {

        if(!strcmp(form->header_name, "Content-Disposition")) {

            if(strstr(form->header_value, "name=\"DISCONNECT\"")) {
                form->state = Login_GetAction;
                form->action = LoginAction_Disconnect;
                *form->action_param = '\0';
            } else if(strstr(form->header_value, "name=\"PASSWORD\"")) {
                form->state = Login_GetPassword;
                form->action = LoginAction_Submit;
                *form->password = '\0';
            } else if(strstr(form->header_value, "name=\"USER\"")) {
                form->state = Login_GetUserName;
                form->action = LoginAction_Submit;
                *form->user = '\0';
            } else if(strstr(form->header_value, "name=\"SUBMIT\"")) {
                form->state = Login_GetAction;
                form->action = LoginAction_Submit;
                *form->action_param = '\0';
            }
        }
    }
}

static int on_header_field (struct multipartparser *parser, const char *data, size_t size)
{
    login_form_data_t *form = (login_form_data_t *)parser->data;

    if (*form->header_value)
        on_header_done(parser);

    if(strlen(form->header_name) + size - 1 < sizeof(form->header_name))
        strncat(form->header_name, data, size);

    return 0;
}

static int on_header_value (struct multipartparser *parser, const char *data, size_t size)
{
    login_form_data_t *form = (login_form_data_t *)parser->data;

    if(strlen(form->header_value) + size - 1 < sizeof(form->header_value))
        strncat(form->header_value, data, size);

    return 0;
}

static int on_headers_complete (struct multipartparser *parser)
{
    if (*((login_form_data_t *)parser->data)->header_value)
        on_header_done(parser);

    return 0;
}

static int on_data (struct multipartparser *parser, const char *data, size_t size)
{
    login_form_data_t *form = (login_form_data_t *)parser->data;

    switch(form->state) {

        case Login_GetAction:
            if(strlen(form->action_param) + size - 1 < sizeof(form->action_param))
                strncat(form->action_param, data, size);
            break;

        case Login_GetUserName:
            if(strlen(form->user) + size - 1 < sizeof(form->user))
                strncat(form->user, data, size);
            break;

        case Login_GetPassword:
            if(strlen(form->password) + size - 1 < sizeof(form->password))
                strncat(form->password, data, size);
            break;

        default:
            break;
    }

    return 0;
}

static int on_part_end (struct multipartparser *parser)
{
    login_form_data_t *form = (login_form_data_t *)parser->data;

    switch(form->state) {

        case Login_Failed:
            cleanup(form);
            break;

        default:
            break;
    }

    form->state = Login_Parsing;

    return 0;
}

static int on_body_end (struct multipartparser *parser)
{
    ((login_form_data_t *)parser->data)->state = Login_Complete;

    return 0;
}

static bool login_start (http_request_t *request, const char *boundary)
{
    if(login_callbacks == NULL && (login_callbacks = malloc(sizeof(struct multipartparser_callbacks)))) {

        multipartparser_callbacks_init(login_callbacks);

        login_callbacks->on_body_begin = on_body_begin;
        login_callbacks->on_part_begin = on_part_begin;
        login_callbacks->on_header_field = on_header_field;
        login_callbacks->on_header_value = on_header_value;
        login_callbacks->on_headers_complete = on_headers_complete;
        login_callbacks->on_data = on_data;
        login_callbacks->on_part_end = on_part_end;
        login_callbacks->on_body_end = on_body_end;
    }

    if(login_callbacks) {

        multipartparser_init(&parser, boundary);
        if((parser.data = malloc(sizeof(login_form_data_t)))) {
            request->private_data = parser.data;
            request->on_request_completed = cleanup;
            memset(parser.data, 0, sizeof(login_form_data_t));
            ((login_form_data_t *)parser.data)->request = request;
        }
    }

    return parser.data != NULL;
}

static size_t login_add_chunk (http_request_t *req, const char *data, size_t size)
{
    return multipartparser_execute(&parser, login_callbacks, data, size);
}

static err_t login_post_receive_data (http_request_t *request, struct pbuf *p)
{
    struct pbuf *q = p;

    login_add_chunk(request, p->payload, p->len);

    while((q = q->next))
        login_add_chunk(request, q->payload, q->len);

    httpd_free_pbuf(request, p);

    return ERR_OK;
}

static void login_post_finished (http_request_t *request, char *response_uri, u16_t response_uri_len)
{
    const char *response;

    login_form_data_t *login_data = (login_form_data_t *)request->private_data;

    login_data->request = request;

    if((response = login(login_data)))
        strcpy(response_uri, response);

    if(request->on_request_completed) {
        request->on_request_completed(request->private_data);
        request->private_data = NULL;
        request->on_request_completed = NULL;
    }
}

static webui_auth_level_t check_authenticated (ip_addr_t ip, const session_id_t *session_id)
{
    webui_auth_t *current = sessions, *previous = NULL;
    uint32_t now = hal.get_elapsed_ticks();

    webui_auth_level_t level = WebUIAuth_Guest;

    while(current) {
        if(now - current->last_access > 360000) {
            if(current == sessions) {
                sessions = current->next;
                free(current);
                current = sessions;
            } else {
                previous->next = current->next;
                free(current);
                current = previous->next;
            }
        } else {
            if (memcmp(&ip, &current->ip, sizeof(ip_addr_t)) == 0 && memcmp(session_id, current->session_id, sizeof(session_id_t)) == 0) {
                current->last_access = now;
                level = current->level;
            }
            previous = current;
            current = current->next;
        }
    }

    return level;
}

webui_auth_level_t get_auth_level (http_request_t *req)
{
    session_id_t session_id;
    webui_auth_level_t auth_level = WebUIAuth_None;

    if(get_session_id(req, &session_id))
        auth_level = check_authenticated(http_get_remote_ip(req), &session_id);

    return auth_level;
}

const char *login_handler_post (http_request_t *request)
{
    int len;
    bool ok;
    char ct[200], *boundary;

    if((len = http_get_header_value_len (request, "Content-Type")) >= 0) {
        http_get_header_value (request, "Content-Type", ct, len);
        if((ok = (boundary = strstr(ct, "boundary=")))) {
            boundary += strlen("boundary=");
            ok = login_start(request, boundary);
        }
    }

    request->post_receive_data = login_post_receive_data;
    request->post_finished = login_post_finished;

    return NULL;
}

const char *login_handler_get (http_request_t *request)
{
    char tmp[30];
    login_form_data_t login_data = {0};

    login_data.request = request;

    if(http_get_param_count(request)) {

        if(http_get_param_value(request, "DISCONNECT", tmp, sizeof(tmp)))
            login_data.action = LoginAction_Disconnect;
        else if(http_get_param_value(request, "SUBMIT", tmp, sizeof(tmp))) {
            login_data.action = LoginAction_Submit;
            if(!http_get_param_value(request, "NEWPASSWORD", login_data.new_password, sizeof(login_data.new_password))) {
                http_get_param_value(request, "USER", login_data.user, sizeof(login_data.user));
                http_get_param_value(request, "PASSWORD", login_data.password, sizeof(login_data.password));
            }
        }
    }

    return login(&login_data);
}

void login_init (void)
{
    if((nvs_address = nvs_alloc(sizeof(webui_settings_t))))
        settings_register(&details);
}

#endif // WEBUI_ENABLE && WEBUI_AUTH_ENABLE
