/*
  webui/server.c - An embedded CNC Controller with rs274/ngc (g-code) support

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

#ifdef ARDUINO
#include "../driver.h"
#else
#include "driver.h"
#endif

#if WEBUI_ENABLE && !defined(ESP_PLATFORM)

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "../networking/urldecode.h"
#include "../networking/websocketd.h"
#include "../networking/httpd.h"
#include "../networking/utils.h"
#include "../networking/strutils.h"
#include "../networking/cJSON.h"
#include "../networking/http_upload.h"

#if SDCARD_ENABLE
#include "./sdcard.h"
#include "../sdcard/sdcard.h"
#endif

#include "commands.h"

#include "../grbl/protocol.h"

#if WEBUI_INFLASH
#include "filedata.h"
#endif
#if WEBUI_AUTH_ENABLE
#include "login.h"
#endif

#ifndef WEBUI_AUTO_REPORT_INTERVAL
#define WEBUI_AUTO_REPORT_INTERVAL 3000 // ms
#endif

extern struct fs_file *fs_create (void);
extern int fs_bytes_left (struct fs_file *file);
extern void fs_register_embedded_files (const embedded_file_t **files);
extern void fs_reset (void);

static bool file_is_json = false;
static uint32_t auto_report_interval = WEBUI_AUTO_REPORT_INTERVAL;
static driver_setup_ptr driver_setup;
static driver_reset_ptr driver_reset;
static on_stream_changed_ptr on_stream_changed;
static on_report_options_ptr on_report_options;
static on_execute_realtime_ptr on_execute_realtime;
static stream_write_ptr pre_stream;
static stream_write_ptr claim_stream;

void data_is_json (void)
{
    file_is_json = true;
}

void stream_changed (stream_type_t type)
{
    if(on_stream_changed)
        on_stream_changed(type);

    if(!(type == StreamType_SDCard || type == StreamType_FlashFs) && hal.stream.write == claim_stream)
        hal.stream.write = pre_stream;
}

bool claim_output (struct fs_file **file)
{
    pre_stream = hal.stream.write;

    claim_stream = (*file = fs_create()) ? hal.stream.write : NULL;

    return claim_stream != NULL;
}

#if !WEBUI_AUTH_ENABLE

static webui_auth_level_t get_auth_level (http_request_t *req)
{
    return WebUIAuth_Admin;
}

#endif

//static ip_addr_t ip;
//static uint16_t port;

//static const char *command (int iIndex, int iNumParams, char *pcParam[], char *pcValue[])
static const char *command (http_request_t *request)
{
    static bool busy;
    bool ok;
    char data[100], *cmd;

    file_is_json = false;

    if(busy)
        return NULL;

    hal.stream.state.webui_connected = busy = true;

    if(http_get_param_value(request, "commandText", data, sizeof(data)) == NULL && http_get_param_value(request, "cmd", data, sizeof(data)) == NULL)
        http_get_param_value(request, "plain", data, sizeof(data));

//    ip = http_get_remote_ip(request);
//    port = http_get_remote_port(request);

    if((cmd = strstr(data, "[ESP"))) {

        struct fs_file *file;
        status_code_t status;

        claim_output(&file);

        cmd += 4;

        uint_fast16_t argc = 0;
        char c, cp = '\0', *args = NULL, **argv = NULL, *tmp, **tmp2, *tmp3;

        if((ok = (args = strchr(cmd, ']')))) {

            *args++ = '\0';

            if(*args) {

                // Trim leading and trailing spaces
                while(*args == ' ')
                    args++;

                if((tmp = args + strlen(args)) != args) {
                    while(*(--tmp) == ' ')
                        *tmp = '\0';
                }

                // remove duplicate delimiters (spaces)
                tmp = tmp3 = args;
                while((c = *tmp++) != '\0') {
                    if(c != ' ' || cp != ' ')
                        *tmp3++ = c;
                    cp = c;
                }
                *tmp3 = '\0';
            }

            // tokenize arguments (if any)
            if(*args) {

                argc = 1;
                tmp = args;
                while((c = *tmp++) != '\0') {
                    if(c == ' ')
                        argc++;
                }

                if(argc == 1)
                    argv = &args;
                else if((ok = !!(argv = tmp2 = malloc(sizeof(char *) * argc)))) {

                    tmp = strtok(args, " ");
                    while(tmp) {
                        *tmp2++ = tmp;
                        tmp = strtok(NULL, " ");
                    }

                    tmp = args;
                    while((c = *tmp) != '\0') {
                        if(c == ' ')
                            *tmp = '\0';
                        tmp++;
                    }
                } else {
                    http_set_response_status(request, "500 Internal server error");
                    hal.stream.write("Failed to generate response");
                }
            }

            ok &= (status = webui_command_handler(atol(cmd), argc, argv, get_auth_level(request))) == Status_OK;

#if WEBUI_AUTH_ENABLE
            if(status == Status_AuthenticationRequired || status == Status_AccessDenied) {
                http_set_response_status(request, status == Status_AuthenticationRequired ? "401 Unauthorized" : "403 Forbidden");
                if(fs_bytes_left(file) == 0)
                    hal.stream.write(status == Status_AuthenticationRequired ? "Login and try again\n" : "Not authorized\n"); // ??
            }
#endif

            if(argc > 1 && argv)
                free(argv);
        }

        fs_close(file);

    } else {

        if(strlen(data) == 1)
            websocketd_RxPutC(*data);

        else {

            size_t len;
            char c, *block = strtok(data, "\n");

            while(block) {

                if((len = strlen(block)) == 2 && *block == 0xC2) {
                    block++;
                    len--;
                }

                while((c = *block++))
                    websocketd_RxPutC(c);

                if(len > 1)
                    websocketd_RxPutC(ASCII_LF);

                block = strtok(NULL, "\n");
            }
        }

        struct fs_file *file = fs_create();

        if(file) {
            hal.stream.write("ok");
            fs_close(file);
        } else {
            busy = false;
            return NULL;
        }
    }

    busy = false;

    http_set_response_header(request, "Cache-Control", "no-cache");

    return file_is_json ? "cgi:qry.json" : "cgi:qry.txt";
}

#if WEBUI_INFLASH

// Virtual spiffs

static void spiffs_on_upload_name_parsed (char *name)
{
    static const char *prefix = "/www/";

    size_t len = strlen(name), plen = strlen(prefix);
    if(*name == '/')
        plen--;

    if(len + plen <= HTTP_UPLOAD_MAX_PATHLENGTH) {
        memmove(name + plen, name, len + 1);
        memcpy(name, prefix, plen);
    }
}

static const char *spiffs_upload_handler (http_request_t *request)
{
    sdcard_upload_handler(request);

    http_upload_on_filename_parsed(spiffs_on_upload_name_parsed);

    return NULL;
}

/**/

#endif

bool is_authorized (http_request_t *req, webui_auth_level_t min_level)
{
#if WEBUI_AUTH_ENABLE
    webui_auth_level_t auth_level;

    if((auth_level = get_auth_level(req)) < min_level) {
        http_set_response_status(req, auth_level < WebUIAuth_User ? "401 Unauthorized" : "403 Forbidden");
        hal.stream.write(auth_level < WebUIAuth_User ? "Login and try again\n" : "Not authorized\n");
        return false;
    }
#endif
    return true;
}

#if WEBUI_AUTH_ENABLE

#endif


static void webui_reset (void)
{
    driver_reset();

    fs_reset();

    if(hal.stream.write == claim_stream)
        hal.stream.write = pre_stream;
}

static void webui_options (bool newopt)
{
    on_report_options(newopt);

    if(!newopt)
        hal.stream.write("[PLUGIN:WebUI v0.04]" ASCII_EOL);
}

static bool webui_setup (settings_t *settings)
{
    bool ok;

    if((ok = driver_setup(settings)))
        sdcard_getfs(); // Mounts SD card if not already mounted

    return ok;
}

#if !WEBUI_AUTH_ENABLE

static const char *login_handler_get (http_request_t *request)
{
    bool ok = false;
    cJSON *root;

    if((root = cJSON_CreateObject())) {

        ok = cJSON_AddStringToObject(root, "status", "ok") != NULL;
        ok &= cJSON_AddStringToObject(root, "authentication_lvl", "admin") != NULL;

        if(ok) {
            char *resp = cJSON_PrintUnformatted(root);
            struct fs_file *file = fs_create();
            hal.stream.write(resp);
            fs_close(file);
            free(resp);
        }

        if(root)
            cJSON_Delete(root);
    }

    return ok ? "cgi:qry.json" : NULL;
}

#endif

static void webui_auto_report (sys_state_t state)
{
    static uint32_t ms = 0;

    if(auto_report_interval > 0 && (hal.get_elapsed_ticks() - ms) >= auto_report_interval) {
        ms = hal.get_elapsed_ticks();
        if(hal.stream.state.webui_connected)
            protocol_enqueue_realtime_command(CMD_STATUS_REPORT);
    }

    on_execute_realtime(state);
}

void webui_init (void)
{
#if WEBUI_AUTH_ENABLE
    login_init();
#endif

    driver_setup = hal.driver_setup;
    hal.driver_setup = webui_setup;

    driver_reset = hal.driver_reset;
    hal.driver_reset = webui_reset;

    on_report_options = grbl.on_report_options;
    grbl.on_report_options = webui_options;

    on_stream_changed = grbl.on_stream_changed;
    grbl.on_stream_changed = stream_changed;

    on_execute_realtime = grbl.on_execute_realtime;
    grbl.on_execute_realtime = webui_auto_report;

    static const httpd_uri_handler_t cgi[] = {
        { .uri = "/command",  .method =  HTTP_Get,  .handler = command },
#if SDCARD_ENABLE
        { .uri = "/upload",   .method =  HTTP_Get,  .handler = sdcard_handler },
        { .uri = "/sdfiles",  .method =  HTTP_Get,  .handler = sdcard_handler },
        { .uri = "/SD/*",     .method =  HTTP_Get,  .handler = sdcard_download_handler },
        { .uri = "/sdcard/*", .method =  HTTP_Get,  .handler = sdcard_download_handler },
        { .uri = "/upload",   .method =  HTTP_Post, .handler = sdcard_upload_handler },
        { .uri = "/sdfiles",  .method =  HTTP_Post, .handler = sdcard_upload_handler },
#endif
        { .uri = "/login",    .method =  HTTP_Get,  .handler = login_handler_get },
#if WEBUI_AUTH_ENABLE
        { .uri = "/login",    .method =  HTTP_Post, .handler = login_handler_post },
#endif
#if WEBUI_INFLASH
        { .uri = "/files",    .method =  HTTP_Post, .handler = spiffs_upload_handler }
#endif
    };

    httpd_register_uri_handlers(cgi, sizeof(cgi) / sizeof(httpd_uri_handler_t));

#if WEBUI_INFLASH
    fs_register_embedded_files(ro_files);
#endif
}

#endif // WEBUI_ENABLE
