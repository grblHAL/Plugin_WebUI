/*
  server.c - An embedded CNC Controller with rs274/ngc (g-code) support

  WebUI backend for https://github.com/luc-github/ESP3D-webui

  Part of grblHAL

  Copyright (c) 2019-2023 Terje Io

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
#if SSDP_ENABLE
#include "../networking/ssdp.h"
#endif

#if WIFI_ENABLE && WIFI_SOFTAP
#include "wifi.h"
#endif

#if SDCARD_ENABLE
#include "sdfs.h"
#include "../sdcard/sdcard.h"
#endif

#include "flashfs.h"

#include "args.h"
#include "login.h"
#include "commands_v2.h"
#include "commands_v3.h"
#include "fs_handlers.h"

#if ESP_PLATFORM
#include "../esp_webui/fs_spiffs.h"
#include "../esp_webui/fs_embedded.h"
#elif WEBUI_INFLASH
#include "fs_embedded.h"
#endif

#include "grbl/vfs.h"

typedef struct {
    websocket_t *websocket;
    uint32_t timeout;
    uint32_t activity;
} webui_client_t;

static bool file_is_json = false, is_v3 = false;
static char sys_path[32] = ""; // Directory where index.html.gz was found
static webui_client_t client;
static driver_setup_ptr driver_setup;
static on_report_options_ptr on_report_options;

static websocket_on_client_connect_ptr on_client_connect;
static websocket_on_client_disconnect_ptr on_client_disconnect;
static websocket_on_protocol_select_ptr on_protocol_select;

char *webui_get_sys_path (void)
{
    return sys_path;
}

void data_is_json (void)
{
    file_is_json = true;
}

#if !WEBUI_AUTH_ENABLE

static webui_auth_level_t get_auth_level (http_request_t *req)
{
    return WebUIAuth_Admin;
}

#endif

void websocket_client_connect (websocket_t *websocket)
{
    char buf[24];

    if(client.websocket == websocket) {
#if WEBUI_AUTH_ENABLE
        client.activity = hal.get_elapsed_ticks();
        client.timeout = login_get_timeout_period();
#endif
        strcat(strcpy(buf, "currentID:"), uitoa((uint32_t)websocket));
        websocket_send_frame(websocket, buf, strlen(buf), false);

        if(!websocket_claim_stream(websocket)) {
            strcat(strcpy(buf, "activeID:"), uitoa((uint32_t)websocket));
            websocket_broadcast_frame(buf, strlen(buf), false); // TODO: only to webui clients?
        }

    } else if(on_client_connect)
        on_client_connect(websocket);
}

void websocket_client_disconnect (websocket_t *websocket)
{
    if(client.websocket && client.websocket != websocket)
        websocket_claim_stream(client.websocket);

    if(on_client_disconnect)
        on_client_disconnect(websocket);
}

void websocket_on_frame_received (websocket_t *websocket, void *data, size_t size)
{
#if WEBUI_AUTH_ENABLE
    if(size > 5 && !strncmp((char *)data, "PING:", 5)) {

        char buf[20];
        uint32_t td = hal.get_elapsed_ticks() - client.activity;


        if((client.timeout = login_get_timeout_period()))
            strcat(strcat(strcpy(buf, "PING:"), uitoa(td > client.timeout ? 0 : client.timeout - td)), td > client.timeout ? ":1" : ":0");
        else
            strcpy(buf, "PING:360000:0");

        websocket_send_frame(websocket, buf, strlen(buf), false);
    }
#endif
}

static char *websocket_protocol_select (websocket_t *websocket, char *protocols, bool *is_binary)
{
    network_info_t *network = networking_get_info();

    if(network->status.services.http && (is_v3 = strlookup(protocols, "webui-v3", ',') >= 0)) {
        *is_binary = true;
         client.websocket = websocket;
         websocket_set_stream_flags(websocket, (io_stream_state_t){ .connected = true, .webui_connected = true });
         websocket_register_frame_handler(websocket, websocket_on_frame_received, false); // claim text frames
    } else
        client.websocket = NULL;

    return is_v3 ? "webui-v3" : (on_protocol_select ? on_protocol_select(websocket, protocols, is_binary) : NULL);
}

static const char *command (http_request_t *request)
{
    static bool busy;

    bool ok;
    char data[100], *cmd, *ping = NULL;
    vfs_file_t *file;

    file_is_json = false;

    if(busy)
        return NULL;

#if WEBUI_ENABLE < 100 // for now... WebUI should connect the websocket before sending commands?
    hal.stream.state.webui_connected = busy = true;
#else
    busy = true;
#endif

#if WEBUI_ENABLE == 2
    if(http_get_param_value(request, "commandText", data, sizeof(data)) == NULL)
        http_get_param_value(request, "plain", data, sizeof(data));
#elif WEBUI_ENABLE == 3
    if(http_get_param_value(request, "cmd", data, sizeof(data)) == NULL)
        ping = http_get_param_value(request, "PING", data, sizeof(data));
#else
    if(http_get_param_value(request, "cmd", data, sizeof(data)) == NULL &&
        (ping = http_get_param_value(request, "PING", data, sizeof(data))) == NULL &&
          http_get_param_value(request, "commandText", data, sizeof(data)) == NULL)
        http_get_param_value(request, "plain", data, sizeof(data));
#endif

    http_set_response_header(request, "Cache-Control", "no-cache");

    if(ping) {

        if(!strcmp(data, "Yes"))
            client.activity = hal.get_elapsed_ticks();

        busy = false;

        return NULL;
    }

    if((cmd = strstr(data, "[ESP"))) {

        if((file = vfs_open("/ram/qry", "w")) == NULL) {
            busy = false;
            http_set_response_status(request, "500 Internal Server Error");
            return NULL;
        }

        status_code_t status;

        cmd += 4;

        uint_fast16_t argc = 0, cmdv;
        char c, cp = '\0', *args = NULL, **argv = NULL, *tmp, **tmp2, *tmp3;

        if((ok = (args = strchr(cmd, ']')))) {

            *args++ = '\0';

            if(*args) {

                // Change escaped spaces into a NBSP pair
                while((tmp = strstr(args, "\\ ")))
                    tmp[0] = tmp[1] = '\xA0'; // NBSP

                // Trim leading and trailing spaces
                while(*args == ' ')
                    args++;

                if((tmp = args + strlen(args)) != args) {
                    while(*(--tmp) == ' ')
                        *tmp = '\0';
                }

                // Remove duplicate delimiters (spaces)
                tmp = tmp3 = args;
                while((c = *tmp++) != '\0') {
                    if(c != ' ' || cp != ' ')
                        *tmp3++ = c;
                    cp = c;
                }
                *tmp3 = '\0';
            }

            // Tokenize arguments (if any)
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
                } else {
                    http_set_response_status(request, "500 Internal Server Error");
                    vfs_puts("Failed to generate response", file);
                }
            }

            // Replace escaped spaces with a space
            for(cmdv = 0; cmdv < argc; cmdv++) {
                tmp = argv[cmdv];
                while((tmp = strstr(tmp, "\xA0\xA0"))) {
                    memmove(tmp, tmp + 1, strlen(tmp));
                    *tmp = ' ';
                }
            }

            cmdv = atol(cmd);

            if(cmdv == 800) {

                is_v3 = false;

                if(argc) {

                    if((tmp = webui_get_arg(argc, argv, "version="))) {
                        is_v3 = *tmp == '3';
                        webui_trim_arg(&argc, argv, "version=");
                    }

                    if(hal.rtc.set_datetime && (tmp = webui_get_arg(argc, argv, "time="))) {

                        struct tm *time;

                        if(strlen(tmp) > 16) {
                            tmp[10] = 'T';
                            tmp[13] = ':';
                            tmp[16] = ':';
                        }
                        time = get_datetime(tmp);
                        hal.rtc.set_datetime(time);
                    }

                    webui_trim_arg(&argc, argv, "time=");
                }
            }

            if(cmdv != 701 || sdcard_busy())
                client.activity = hal.get_elapsed_ticks();

#if WEBUI_ENABLE == 1

            if(!is_v3)
                is_v3 = cmdv == 701;

            if(is_v3)
                ok &= (status = webui_v3_command_handler(cmdv, argc, argv, get_auth_level(request), file)) == Status_OK;
            else
                ok &= (status = webui_v2_command_handler(cmdv, argc, argv, get_auth_level(request), file)) == Status_OK;

#elif WEBUI_ENABLE == 2
            ok &= (status = webui_v2_command_handler(cmdv, argc, argv, get_auth_level(request), file)) == Status_OK;
#else
            ok &= (status = webui_v3_command_handler(cmdv, argc, argv, get_auth_level(request), file)) == Status_OK;
#endif

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
        busy = false;

        return file_is_json ? "/ram/qry.json" : "/ram/qry.txt";
    }

    if(*data == '\0')
        websocketd_RxPutC(ASCII_LF);

    else if(*(data + 1) == '\0')
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

    busy = false;

    return "/stream/qry.txt";
}

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

        char *ip;
        bool internal = false;
        ip4_addr_t ap_ip;
        ip_addr_t host_ip = http_get_remote_ip(request);
        ap_list_t *ap_list = wifi_get_aplist();

        if(ap_list) { // Request is from local STA?
            internal = ap_list->ap_selected && memcmp(&ap_list->ip_addr, &host_ip, sizeof(ip4_addr_t)) == 0;
            wifi_release_aplist();
        }

        // if not from local AP redirect
#if ESP_PLATFORM
        if(!internal && (ip = setting_get_value(setting_get_details(Setting_IpAddress2, NULL), 0)) && inet_pton(AF_INET, ip, &ap_ip) == 1) {
#else
        if(!internal && (ip = setting_get_value(setting_get_details(Setting_IpAddress2, NULL), 0)) && ip4addr_aton(ip, &ap_ip) == 1) {
#endif 
            if(memcmp(&host_ip, &ap_ip, sizeof(ip4_addr_t))) {

                char loc[75];
                sprintf(loc, "http://%s/ap_login.html", network->status.ip);

                return redirect_html_get_handler(request, loc);
            }
        }
    }

    return http_get_uri(request);
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
                        ok &= cJSON_AddStringToObject(ap, "security", wifi_get_authmode_name(ap_list->ap_records[i].authmode)) != NULL;
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
                vfs_file_t *file = vfs_open("/ram/data.json", "w");
                vfs_puts(resp, file);
                vfs_close(file);

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

    vfs_file_t *file = vfs_open("/ram/data.txt", "w");
    vfs_puts("Connecting...", file);
    vfs_close(file);

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

#if WEBUI_ENABLE != 2

static const char *config_handler_get (http_request_t *request)
{
    char data[10];
    bool is_json = false;
    vfs_file_t *file;

    if(http_get_param_value(request, "json", data, sizeof(data)))
        is_json = *data == 'y';

    if((file = vfs_open("/ram/qry", "w")) == NULL) {
        http_set_response_status(request, "500 Internal Server Error");
        return NULL;
    }

    webui_v3_get_system_status(401, 0, NULL, is_json, file);

    vfs_close(file);

    return is_json ? "/ram/qry.json" : "/ram/qry.txt";
}

#endif

bool file_search (char *path, const char *uri, vfs_file_t **file, const char *mode)
{
    if(*path == '\0' || (*file = vfs_open(strcat(path, uri + 1), mode)) == NULL) {
#if WEBUI_INFLASH
        if((*file = vfs_open(strcat(strcpy(path, "/www"), uri), mode)) == NULL)
            *file = vfs_open(strcat(strcpy(path, "/embedded"), uri), mode);
#else
        *file = vfs_open(strcat(strcpy(path, "/www"), uri), mode);
#endif
    }

    return *file != NULL;
}

const char *file_redirect (http_request_t *request, const char *uri, vfs_file_t **file, const char *mode)
{
    char path[32];
    vfs_drive_t *flashfs = fs_get_flash_drive();

    if(flashfs)
        strcpy(path, flashfs->path);
    else
        *path = '\0';

    if(!strcmp(uri, "/")) {

#if WEBUI_INFLASH
        char fallback[5];
        if(http_get_param_value(request, "forcefallback", fallback, sizeof(fallback)) != NULL && !strcmp(fallback, "yes")) {
            if((*file = vfs_open("/embedded/index.html.gz", mode))) {
                uri = "/index.html";
                request->encoding = HTTPEncoding_GZIP;
                strcpy(sys_path, path);
            }
            return uri;
        }
#endif

        if(file_search(path, "/index.html.gz", file, mode))
            request->encoding = HTTPEncoding_GZIP;
        else
            file_search(path, "/index.html", file, mode);

        if(*file) {
            char *s = strstr(path, "index.html");
            if(s)
                *s = '\0';
            vfs_fixpath(path);
            strcpy(sys_path, flashfs == NULL || strcmp(path, "/embedded") ? path : flashfs->path);
            uri = "/index.html";
        }
    } else if(!strcmp(uri, "/favicon.ico") || !strcmp(uri, "/preferences.json"))
        file_search(strcpy(path, *sys_path == '\0' ? "/" : sys_path), uri, file, mode);
#if WIFI_ENABLE && WIFI_SOFTAP
    else if(!strcmp(uri, "/ap_login.html"))
        file_search(path, uri, file, mode);
#endif

    if(*file == NULL && strlookup(".gz", uri, '.') == -1) {
        if((*file = vfs_open(strcat((char *)uri, ".gz"), mode)))
            request->encoding = HTTPEncoding_GZIP;
        *(strchr(uri, '\0') - 3) = '\0';
    }

    return uri;
}

static void webui_options (bool newopt)
{
    on_report_options(newopt);

    if(!newopt)
        hal.stream.write("[PLUGIN:WebUI v0.20]" ASCII_EOL);
}

void webui_init (void)
{
    login_init(); // handles WebUI settings so always call!

    driver_setup = hal.driver_setup;
    hal.driver_setup = webui_setup;

    on_report_options = grbl.on_report_options;
    grbl.on_report_options = webui_options;

    on_protocol_select = websocket.on_protocol_select;
    websocket.on_protocol_select = websocket_protocol_select;

    on_client_connect = websocket.on_client_connect;
    websocket.on_client_connect = websocket_client_connect;

    on_client_disconnect = websocket.on_client_disconnect;
    websocket.on_client_disconnect = websocket_client_disconnect;

    httpd.on_open_file_failed = file_redirect;

#if WEBUI_ENABLE == 1 // All WebUI versions supported

    static const httpd_uri_handler_t cgi[] = {
        { .uri = "/command",  .method = HTTP_Get,     .handler = command },
  #if SDCARD_ENABLE
        { .uri = "/upload",   .method = HTTP_Get,     .handler = sdcard_handler },
        { .uri = "/sd/*",     .method = HTTP_Get,     .handler = sdcard_download_handler },
        { .uri = "/SD/*",     .method = HTTP_Get,     .handler = sdcard_download_handler }, // v2
        { .uri = "/sdcard/*", .method = HTTP_Get,     .handler = sdcard_download_handler },
        { .uri = "/upload",   .method = HTTP_Post,    .handler = sdcard_upload_handler },
        { .uri = "/sdfiles",  .method = HTTP_Get,     .handler = sdcard_handler },
        { .uri = "/sdfiles",  .method = HTTP_Post,    .handler = sdcard_upload_handler },
  #endif
        { .uri = "/files",    .method = HTTP_Get,     .handler = flashfs_handler },
        { .uri = "/files",    .method = HTTP_Post,    .handler = flashfs_upload_handler },
        { .uri = "/login",    .method = HTTP_Get,     .handler = login_handler_get },
        { .uri = "/config",   .method = HTTP_Get,     .handler = config_handler_get }, // v3
  #if WEBUI_AUTH_ENABLE
        { .uri = "/login",    .method = HTTP_Post,    .handler = login_handler_post },
  #endif
  #if SSDP_ENABLE
        { .uri = "/" SSDP_LOCATION_DOC, .method = HTTP_Get, .handler = ssdp_handler_get },
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

#elif WEBUI_ENABLE == 2 // WebUI v2

    static const httpd_uri_handler_t cgi[] = {
        { .uri = "/command",  .method = HTTP_Get,     .handler = command },
  #if SDCARD_ENABLE
        { .uri = "/upload",   .method = HTTP_Get,     .handler = sdcard_handler },
        { .uri = "/sd/*",     .method = HTTP_Get,     .handler = sdcard_download_handler },
        { .uri = "/SD/*",     .method = HTTP_Get,     .handler = sdcard_download_handler }, // v2
        { .uri = "/sdcard/*", .method = HTTP_Get,     .handler = sdcard_download_handler },
        { .uri = "/upload",   .method = HTTP_Post,    .handler = sdcard_upload_handler },
        { .uri = "/sdfiles",  .method = HTTP_Get,     .handler = sdcard_handler },
        { .uri = "/sdfiles",  .method = HTTP_Post,    .handler = sdcard_upload_handler },
  #endif
        { .uri = "/files",    .method = HTTP_Get,     .handler = flashfs_handler },
        { .uri = "/files",    .method = HTTP_Post,    .handler = flashfs_upload_handler },
        { .uri = "/login",    .method = HTTP_Get,     .handler = login_handler_get },
  #if WEBUI_AUTH_ENABLE
        { .uri = "/login",    .method = HTTP_Post,    .handler = login_handler_post },
  #endif
  #if SSDP_ENABLE
        { .uri = "/" SSDP_LOCATION_DOC, .method = HTTP_Get, .handler = ssdp_handler_get },
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

#else // WebUI v3

    static const httpd_uri_handler_t cgi[] = {
        { .uri = "/command",  .method = HTTP_Get,     .handler = command },
  #if SDCARD_ENABLE
        { .uri = "/upload",   .method = HTTP_Get,     .handler = sdcard_handler },
        { .uri = "/sd/*",     .method = HTTP_Get,     .handler = sdcard_download_handler },
        { .uri = "/upload",   .method = HTTP_Post,    .handler = sdcard_upload_handler },
        { .uri = "/sdfiles",  .method = HTTP_Get,     .handler = sdcard_handler },
        { .uri = "/sdfiles",  .method = HTTP_Post,    .handler = sdcard_upload_handler },
  #endif
        { .uri = "/files",    .method = HTTP_Get,     .handler = flashfs_handler },
        { .uri = "/files",    .method = HTTP_Post,    .handler = flashfs_upload_handler },
        { .uri = "/login",    .method = HTTP_Get,     .handler = login_handler_get },
        { .uri = "/config",   .method = HTTP_Get,     .handler = config_handler_get },
//        { .uri = "/updatefw", .method = HTTP_Post,    .handler = sdcard_upload_handler },
  #if WEBUI_AUTH_ENABLE
        { .uri = "/login",    .method = HTTP_Post,    .handler = login_handler_post },
  #endif
  #if SSDP_ENABLE
        { .uri = "/" SSDP_LOCATION_DOC, .method = HTTP_Get, .handler = ssdp_handler_get },
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

#endif // WEBUI_ENABLE

    httpd_register_uri_handlers(cgi, sizeof(cgi) / sizeof(httpd_uri_handler_t));

    fs_ram_mount();
    fs_stream_mount();

#if WEBUI_INFLASH || ESP_PLATFORM
    fs_embedded_mount();
#endif
#if xESP_PLATFORM
    fs_spiffs_mount();
#endif
}

#endif // WEBUI_ENABLE
