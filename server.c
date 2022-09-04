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

#if WEBUI_ENABLE

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "../networking/websocketd.h"
#include "../networking/networking.h"
#include "../networking/utils.h"
#include "../networking/strutils.h"
#include "../networking/cJSON.h"
#include "../networking/http_upload.h"
#include "../networking/fs_ram.h"
#include "../networking/fs_stream.h"

#if WIFI_ENABLE && WIFI_SOFTAP
#include "wifi.h"
#include "esp_wifi.h"
#endif

#if SDCARD_ENABLE
#include "./sdcard.h"
#include "../sdcard/sdcard.h"
#endif

#include "commands_v2.h"
#include "commands_v3.h"

#include "../grbl/protocol.h"

#if ESP_PLATFORM
#include "../esp_webui/fs_embedded.h"
#elif WEBUI_INFLASH
#include "fs_embedded.h"
#endif
#if WEBUI_AUTH_ENABLE
#include "login.h"
#endif

#ifndef WEBUI_AUTO_REPORT_INTERVAL
#define WEBUI_AUTO_REPORT_INTERVAL 0 // ms
#endif

#include "grbl/vfs.h"

static bool file_is_json = false, is_v3 = false;
static uint32_t auto_report_interval = WEBUI_AUTO_REPORT_INTERVAL;
static driver_setup_ptr driver_setup;
static driver_reset_ptr driver_reset;
static on_stream_changed_ptr on_stream_changed;
static on_report_options_ptr on_report_options;
static on_execute_realtime_ptr on_execute_realtime;
static websocket_on_protocol_select_ptr on_protocol_select;
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

bool claim_output (vfs_file_t **file)
{
    pre_stream = hal.stream.write;

    claim_stream = (*file = vfs_open("/stream/qry", "w")) ? hal.stream.write : NULL;

    return claim_stream != NULL;
}

#if !WEBUI_AUTH_ENABLE

static webui_auth_level_t get_auth_level (http_request_t *req)
{
    return WebUIAuth_Admin;
}

#endif

static char *websocket_protocol_select (char *protocols, bool *is_binary)
{
    if((is_v3 = strlookup(protocols, "webui-v3", ',') >= 0))
        *is_binary = true;

    return is_v3 ? "webui-v3" : (on_protocol_select ? on_protocol_select(protocols, is_binary) : NULL);
}

//static ip_addr_t ip;
//static uint16_t port;

//static const char *command (int iIndex, int iNumParams, char *pcParam[], char *pcValue[])
static const char *command (http_request_t *request)
{
    static bool busy;

    bool ok;
    char data[100], *cmd;
    vfs_file_t *file;

    file_is_json = false;

    if(busy)
        return NULL;

    hal.stream.state.webui_connected = busy = true;

    if(http_get_param_value(request, "commandText", data, sizeof(data)) == NULL && http_get_param_value(request, "cmd", data, sizeof(data)) == NULL)
        http_get_param_value(request, "plain", data, sizeof(data));

//    ip = http_get_remote_ip(request);
//    port = http_get_remote_port(request);

    http_set_response_header(request, "Cache-Control", "no-cache");

    if((cmd = strstr(data, "[ESP"))) {

        if((file = vfs_open("/stream/qry", "w")) == NULL) {
            busy = false;
            http_set_response_status(request, "500 Internal Server Error");
            return NULL;
        }

        status_code_t status;

//        claim_output(&file);

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
                    http_set_response_status(request, "500 Internal Server Error");
                    vfs_puts("Failed to generate response", file);
                }
            }

            uint_fast16_t cmdv = atol(cmd);

            if(cmdv == 800 && argc) {

                uint_fast16_t idx = argc;

                is_v3 = false;

                do {
                    if(!strncmp(argv[--idx], "version", 7))
                        is_v3 = argv[idx][8] == '3';
                } while(idx);

                if(hal.rtc.set_datetime) {
 
                    struct tm time;

                    idx = argc;
                    tmp = NULL;

                    do {
                        if(!strncmp(argv[--idx], "time", 4))
                            tmp = &argv[idx][5];
                    } while(idx && tmp == NULL);

                    if(tmp && strtotime(tmp, &time))
                        hal.rtc.set_datetime(&time);
                }
            }

            if(!is_v3)
                is_v3 = cmdv == 701;

            if(is_v3)
                ok &= (status = webui_v3_command_handler(cmdv, argc, argv, get_auth_level(request), file)) == Status_OK;
            else
                ok &= (status = webui_v2_command_handler(cmdv, argc, argv, get_auth_level(request), file)) == Status_OK;

#if WEBUI_AUTH_ENABLE
            if(status == Status_AuthenticationRequired || status == Status_AccessDenied) {
                http_set_response_status(request, status == Status_AuthenticationRequired ? "401 Unauthorized" : "403 Forbidden");
                if(vfs_tell(file) == 0)
                    vfs_puts(status == Status_AuthenticationRequired ? "Login and try again\n" : "Not authorized\n", file); // ??
            }
#endif

            if(argc > 1 && argv)
                free(argv);
        }

        vfs_close(file);

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

        if((file = vfs_open("/stream/qry.txt", "w")) == NULL) {
            busy = false;
            http_set_response_status(request, "500 Internal Server Error");
            return NULL;
        }

        vfs_puts("ok", file);
        vfs_close(file);
    }

    busy = false;

    return file_is_json ? "/stream/qry.json" : "/stream/qry.txt";
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

#if WIFI_ENABLE && WIFI_SOFTAP

/* Handler to redirect incoming GET request for /index.html to /
 * This can be overridden by uploading file with same name */
static const char *redirect_html_get_handler(http_request_t *request, char *location)
{
    http_set_response_status(request, "307 Temporary Redirect");
    http_set_response_header(request, "Location", location);

    return NULL;
}

static const char *get_handler (http_request_t *request)
{
    network_info_t *network = networking_get_info();

    if(network->status.services.dns) { // captive portal, redirect requests to ourself...

        if (!strcmp(http_get_uri(request), "/ap_login.html"))
            return http_get_uri(request);

        bool internal = false;
        ip_addr_t ip = http_get_remote_ip(request);
        char aip[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET, &ip, aip, INET6_ADDRSTRLEN);

        ap_list_t *ap_list = wifi_get_aplist();

        if(ap_list) { // Request is from local STA?
            internal = ap_list->ap_selected && memcmp(&ap_list->ip_addr, &ip, sizeof(ip4_addr_t)) == 0;
            wifi_release_aplist();
        }

        wifi_settings_t *settings = get_wifi_settings();

        // From local AP?
        if(!internal && memcmp(&settings->ap.network.ip, &ip, sizeof(ip4_addr_t))) {

            char loc[75];
            sprintf(loc, "http://%s/ap_login.html", network->status.ip);

            return redirect_html_get_handler(request, loc);
        }
    }

    return http_get_uri(request);
}

static char *getAuthModeName (wifi_auth_mode_t authmode)
{
    static char mode[15];

    sprintf(mode, "%s",
            authmode == WIFI_AUTH_OPEN ? "open" :
            authmode == WIFI_AUTH_WEP ? "wep" :
            authmode == WIFI_AUTH_WPA_PSK ? "wpa-psk" :
            authmode == WIFI_AUTH_WPA2_PSK ? "wpa-psk" :
            authmode == WIFI_AUTH_WPA_WPA2_PSK ? "wpa-wpa2-psk" :
            authmode == WIFI_AUTH_WPA2_ENTERPRISE ? "wpa-eap" :
            "unknown");

    return mode;
}

static const char *wifi_scan_handler (http_request_t *request)
{
    bool ok = false;
    ap_list_t *ap_list = wifi_get_aplist();

    if(ap_list && ap_list->ap_records) {

        cJSON *root;

        if((root = cJSON_CreateObject())) {

            cJSON *ap, *aps;

            ok = cJSON_AddStringToObject(root, "ap", ap_list->ap_selected ? (char *)ap_list->ap_selected : "") != NULL;
            ok &= cJSON_AddStringToObject(root, "status", ap_list->ap_status) != NULL;

            if(ap_list->ap_selected)
                cJSON_AddStringToObject(root, "ip", ip4addr_ntoa(&ap_list->ip_addr));

            if((aps = cJSON_AddArrayToObject(root, "aplist"))) {

                for(int i = 0; i < ap_list->ap_num; i++) {
                    if((ok = (ap = cJSON_CreateObject()) != NULL))
                    {
                        ok = cJSON_AddStringToObject(ap, "ssid", (char *)ap_list->ap_records[i].ssid) != NULL;
                        ok &= cJSON_AddStringToObject(ap, "security", getAuthModeName(ap_list->ap_records[i].authmode)) != NULL;
                        ok &= cJSON_AddNumberToObject(ap, "primary", (double)ap_list->ap_records[i].primary) != NULL;
                        ok &= cJSON_AddNumberToObject(ap, "rssi",  (double)ap_list->ap_records[i].rssi) != NULL;
                        if(ok)
                            cJSON_AddItemToArray(aps, ap);
                    }
                }
            }

            if(ok) {
                char *resp = cJSON_PrintUnformatted(root);
#if xCORS_ENABLE
                http_set_response_header(req, "Access-Control-Allow-Origin", "*");
                http_set_response_header(req, "Access-Control-Allow-Methods", "POST,GET,OPTIONS");
#endif
                vfs_file_t *response = vfs_open("/ram/data.json", "w");
                vfs_puts(resp, file);
                vfs_close(response);

                free(resp);
            }

            if(root)
                cJSON_Delete(root);
        }

        if(!ok)
            http_set_response_status(request, "500 Internal Server Error");
    } else
        http_set_response_status(request, "500 Internal Server Error");

    if(ap_list)
        wifi_release_aplist();

    return ok ? "/ram/data.json" : NULL;
}

typedef struct {
    size_t content_len;
    char payload[1];
} wifi_login_data_t;

static err_t wifi_login_receive_data (http_request_t *request, struct pbuf *p)
{
//    struct pbuf *q = p;

    wifi_login_data_t *login = (wifi_login_data_t *)request->private_data;

    if(login)
        memcpy(&login->payload[0 /*dav.content_len - request->*/], p->payload, p->len);
/*
    while((q = q->next))
        http_upload_chunk(request, q->payload, q->len);
*/
    httpd_free_pbuf(request, p);

    return ERR_OK;
}

static void wifi_login_receive_finished (http_request_t *request, char *response_uri, u16_t response_uri_len)
{
    bool ok;
    cJSON *cred;
    wifi_login_data_t *login = (wifi_login_data_t *)request->private_data;

    if((ok = (cred = cJSON_Parse(login->payload)))) {
        cJSON *ssid = cJSON_GetObjectItemCaseSensitive(cred, "ssid");
        cJSON *password = cJSON_GetObjectItemCaseSensitive(cred, "password");

        ok = ssid && password && wifi_ap_connect(ssid->valuestring, password->valuestring);

        cJSON_Delete(cred);
    }

    if(ok) {
        http_set_response_status(request, "202 Accepted");
    } else
        http_set_response_status(request, "400 Bad Request");

    vfs_file_t *response = vfs_open("/ram/data.txt", "w");

    vfs_puts("Connecting...", file);

    vfs_close(response);

    strcpy(response_uri, "/ram/data.txt");
}

void wifi_login_completed (void *data)
{
    if(data)
        free(data);
}

static const char *wifi_connect_handler (http_request_t *request)
{
    wifi_login_data_t *login;
    char *value = NULL;
    int content_len = 0, vlen = http_get_header_value_len(request, "Content-Length");

    if(vlen > 0 && (value = malloc(vlen + 1))) {

        http_get_header_value(request, "Content-Length", value, vlen);
        content_len = atoi(value); // use strtol? https://www.cplusplus.com/reference/cstdlib/strtol/
        if (content_len == 0) {
            /* if atoi returns 0 on error, fix this */
            if ((value[0] != '0') || (value[1] != '\r'))
                content_len = 0;
        }

        free(value);
    }

    if(content_len && (request->private_data = login = malloc(sizeof(wifi_login_data_t) + content_len)) != NULL) {

        login->content_len = content_len;
        request->post_receive_data = wifi_login_receive_data;
        request->post_finished = wifi_login_receive_finished;
        request->on_request_completed = wifi_login_completed;

    } else
        http_set_response_status(request, content_len ? "500 Internal Server Error" : "400 Bad Request");

    return NULL;
}

static const char *wifi_disconnect_handler (http_request_t *request)
{
    bool disconnect = false;

    ap_list_t *ap_list = wifi_get_aplist();

    if(ap_list) {
        disconnect = ap_list->ap_selected;
        wifi_release_aplist();
    }

    if(disconnect)
        wifi_ap_connect(NULL, NULL);

    http_set_response_status(request, "202 Accepted");

    return NULL;
}

#if CORS_ENABLE
static esp_err_t wifi_options_handler (httpd_req_t *req)
{
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Access-Control-Request-Headers", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");

    return wifi_scan_handler(req);
}
#endif

#endif // WIFI_ENABLE && WIFI_SOFTAP

bool is_authorized (http_request_t *req, webui_auth_level_t min_level, vfs_file_t *file)
{
#if WEBUI_AUTH_ENABLE
    webui_auth_level_t auth_level;

    if((auth_level = get_auth_level(req)) < min_level) {
        http_set_response_status(req, auth_level < WebUIAuth_User ? "401 Unauthorized" : "403 Forbidden");
        vfs_puts(auth_level < WebUIAuth_User ? "Login and try again\n" : "Not authorized\n", file);
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

    if(hal.stream.write == claim_stream)
        hal.stream.write = pre_stream;
}

static void webui_options (bool newopt)
{
    on_report_options(newopt);

    if(!newopt)
        hal.stream.write("[PLUGIN:WebUI v0.05]" ASCII_EOL);
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
            vfs_file_t *file = vfs_open("/ram/qry.json", "w");
            vfs_puts(resp, file);
            vfs_close(file);
            free(resp);
        }

        if(root)
            cJSON_Delete(root);
    }

    return ok ? "/ram/qry.json" : NULL;
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


void file_redirect (const char *uri, vfs_file_t **file, const char *mode)
{
    if(!strcmp(uri, "/favicon.ico")) {
        if((*file = vfs_open("/www/favicon.ico", mode)) == NULL)
            *file = vfs_open("/embedded/favicon.ico", mode);
    } else if(!strcmp(uri, "/preferences.json"))
        *file = vfs_open("/www/preferences.json", mode);
#if WIFI_ENABLE && WIFI_SOFTAP
    else if(!strcmp(uri, "/ap_login.html")) {
        if((*file = vfs_open("/www/ap_login.html", mode)) == NULL)
            *file = vfs_open("/embedded/ap_login.html", mode);
    }
#endif
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

    on_protocol_select = websocket.on_protocol_select;
    websocket.on_protocol_select = websocket_protocol_select;

    httpd.on_open_file_failed = file_redirect;

    static const httpd_uri_handler_t cgi[] = {
        { .uri = "/command",  .method = HTTP_Get,     .handler = command },
#if SDCARD_ENABLE
        { .uri = "/upload",   .method = HTTP_Get,     .handler = sdcard_handler },
        { .uri = "/sdfiles",  .method = HTTP_Get,     .handler = sdcard_handler },
        { .uri = "/sd/*",     .method = HTTP_Get,     .handler = sdcard_download_handler },
        { .uri = "/sdcard/*", .method = HTTP_Get,     .handler = sdcard_download_handler },
        { .uri = "/upload",   .method = HTTP_Post,    .handler = sdcard_upload_handler },
        { .uri = "/sdfiles",  .method = HTTP_Post,    .handler = sdcard_upload_handler },
#endif
        { .uri = "/login",    .method = HTTP_Get,     .handler = login_handler_get },
#if WEBUI_AUTH_ENABLE
        { .uri = "/login",    .method = HTTP_Post,    .handler = login_handler_post },
#endif
#if WEBUI_INFLASH
        { .uri = "/files",    .method = HTTP_Post,    .handler = spiffs_upload_handler },
#endif
#if WIFI_ENABLE && WIFI_SOFTAP
        { .uri = "/wifi",     .method = HTTP_Get,     .handler  = wifi_scan_handler },
        { .uri = "/wifi",     .method = HTTP_Post,    .handler  = wifi_connect_handler },
        { .uri = "/wifi",     .method = HTTP_Delete,  .handler  = wifi_disconnect_handler },
  #if CORS_ENABLE
        { .uri = "/wifi",     .method = HTTP_Options, .handler  = wifi_options_handler },
  #endif
        { .uri = "/*",        .method = HTTP_Get,     .handler = get_handler }, // Must be last!
#endif
    };

    httpd_register_uri_handlers(cgi, sizeof(cgi) / sizeof(httpd_uri_handler_t));

    fs_ram_mount();
    fs_stream_mount();

#if WEBUI_INFLASH || ESP_PLATFORM
    fs_embedded_mount();
#endif
}

#endif // WEBUI_ENABLE
