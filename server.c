/*
  webui/server.c - An embedded CNC Controller with rs274/ngc (g-code) support

  WebUI backend for https://github.com/luc-github/ESP3D-webui

  Part of grblHAL

  Copyright (c) 2019-2021 Terje Io

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

#include "../networking/urldecode.h"
#include "../networking/WsStream.h"
#include "../networking/httpd.h"
#include "../networking/utils.h"
#include "../networking/strutils.h"
#include "../networking/cJSON.h"
#include "../networking/http_upload.h"
#include "../sdcard/sdcard.h"

#include "commands.h"

#include "grbl/nvs_buffer.h"

extern struct fs_file *fs_create (void);
void fs_reset (void);

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

static bool file_is_json = false;
static driver_setup_ptr driver_setup;
static driver_reset_ptr driver_reset;
static on_stream_changed_ptr on_stream_changed;
static on_report_options_ptr on_report_options;
static stream_write_ptr pre_stream;
static stream_write_ptr claim_stream;
#if WEBUI_AUTH_ENABLE
static webui_auth_t *sessions = NULL;
static webui_auth_level_t get_auth_level (http_request_t *request);
static webui_settings_t webui;
static nvs_address_t nvs_address;
static void webui_settings_restore (void);
static void webui_settings_load (void);
bool is_authorized (http_request_t *req, webui_auth_level_t min_level);
#endif

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

//static const char *command (int iIndex, int iNumParams, char *pcParam[], char *pcValue[])
static const char *command (http_request_t *request)
{
    static bool busy;
    bool ok;
    char data[100], *cmd;

    file_is_json = false;

    if(busy)
        return NULL;

    busy = true;

    if(http_get_param_value(request, "commandText", data, sizeof(data)) == NULL)
        http_get_param_value(request, "plain", data, sizeof(data));

    if((cmd = strstr(data, "[ESP"))) {

        struct fs_file *file;

        claim_output(&file);

        cmd += 4;

        char *args = NULL;

        if((ok = (args = strchr(cmd, ']')))) {
            *args++ = '\0';

#if WEBUI_AUTH_ENABLE
//            if((ok = is_authorized(request, get_auth_required(atol(cmd), args))))
#endif

            ok = webui_command_handler(atol(cmd), args) == Status_OK;
        }

        fs_close(file);

    } else {


        if(strlen(data) == 1)
            WsStreamRxInsert(*data);

        else {

            size_t len;
            char c, *block = strtok(data, "\n");

            while(block) {

                if((len = strlen(block)) == 2 && *block == 0xC2) {
                    block++;
                    len--;
                }

                while((c = *block++))
                    WsStreamRxInsert(c);

                if(len > 1)
                    WsStreamRxInsert(ASCII_LF);

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

#if SDCARD_ENABLE

// add file to the JSON response array
static bool add_file (cJSON *files, char *path, FILINFO *file)
{
    bool ok;

    cJSON *fileinfo;

    if((ok = (fileinfo = cJSON_CreateObject()) != NULL))
    {
        ok = cJSON_AddStringToObject(fileinfo, "name", file->fname) != NULL;
        ok &= cJSON_AddStringToObject(fileinfo, "shortname", file->fname) != NULL;
        ok &= cJSON_AddStringToObject(fileinfo, "datetime", "") != NULL;
        if(file->fattrib & AM_DIR)
            ok &= cJSON_AddNumberToObject(fileinfo, "size", -1.0) != NULL;
        else
            ok &= cJSON_AddStringToObject(fileinfo, "size", btoa(file->fsize)) != NULL;
    }

    return ok && cJSON_AddItemToArray(files, fileinfo);
}

static FRESULT sd_scan_dir (cJSON *files, char *path, uint_fast8_t depth)
{
#if defined(ESP_PLATFORM)
    FF_DIR dir;
#else
    DIR dir;
#endif
    FILINFO fno;
    FRESULT res;
    bool subdirs = false;
#if _USE_LFN
    static TCHAR lfn[_MAX_LFN + 1];   /* Buffer to store the LFN */
    fno.lfname = lfn;
    fno.lfsize = sizeof(lfn);
#endif

   if((res = f_opendir(&dir, path)) != FR_OK)
        return res;

   // Pass 1: Scan files
    while(true) {

        if((res = f_readdir(&dir, &fno)) != FR_OK || fno.fname[0] == '\0')
            break;

        subdirs |= fno.fattrib & AM_DIR;

        if(!(fno.fattrib & AM_DIR))
            add_file(files, path, &fno);
    }

    if((subdirs = (subdirs && depth)))
        f_readdir(&dir, NULL); // Rewind

    // Pass 2: Scan directories
    while(subdirs) {

        if((res = f_readdir(&dir, &fno)) != FR_OK || *fno.fname == '\0')
            break;

        if((fno.fattrib & AM_DIR) && strcmp(fno.fname, "System Volume Information")) {

            size_t pathlen = strlen(path);
//          if(pathlen + strlen(get_name(&fno)) > (MAX_PATHLEN - 1))
                //break;
            add_file(files, path, &fno);
            if(depth > 1) {
                sprintf(&path[pathlen], "/%s", fno.fname);
                if((res = sd_scan_dir(files, path, depth - 1)) != FR_OK)
                    break;
                path[pathlen] = '\0';
            }
        }
    }

#if defined(__MSP432E401Y__) || defined(ESP_PLATFORM)
    f_closedir(&dir);
#endif

    return res;
}

static bool sd_ls (void *request, char *path, char *status)
{
    bool ok;
    cJSON *root = cJSON_CreateObject(), *files = NULL;

    if((ok = (root && (files = cJSON_AddArrayToObject(root, "files"))))) {

        if(strlen(path) > 1)
            path[strlen(path) - 1] = '\0';

        sd_scan_dir(files, path, 1);

        cJSON_AddStringToObject(root, "path", path);

        FATFS *fs;
        DWORD fre_clust, used_sect, tot_sect;

        if(f_getfree("", &fre_clust, &fs) == FR_OK) {
            tot_sect = (fs->n_fatent - 2) * fs->csize;
            used_sect = tot_sect - fre_clust * fs->csize;
            uint32_t pct_used = (used_sect * 100) / tot_sect;
            cJSON_AddStringToObject(root, "total", btoa(tot_sect << 9)); // assuming 512 byte sector size
            cJSON_AddStringToObject(root, "used", btoa(used_sect << 9));
            cJSON_AddStringToObject(root, "occupation", uitoa(pct_used == 0 ? 1 : pct_used));
        }
        cJSON_AddStringToObject(root, "mode", "direct");
        cJSON_AddStringToObject(root, "status", status);

        char *resp = cJSON_PrintUnformatted(root);

        data_is_json();

        hal.stream.write(resp);

        free(resp);

        http_set_response_header(request, "Cache-Control", "no-cache");
    }

    if(root)
        cJSON_Delete(root);

    return ok;
}

static bool sd_rmdir (char *path)
{
    bool ok = true;

#if defined(ESP_PLATFORM)
    FF_DIR dir;
#else
    DIR dir;
#endif
    FILINFO fno;

#if _USE_LFN
    static TCHAR lfn[_MAX_LFN + 1];   /* Buffer to store the LFN */
    fno.lfname = lfn;
    fno.lfsize = sizeof(lfn);
#endif

   if(f_opendir(&dir, path) != FR_OK)
        return false;

    size_t pathlen = strlen(path);

    while(ok) {

        if(f_readdir(&dir, &fno) != FR_OK || *fno.fname == '\0')
            break;

        strcat(strcat(path, "/"), fno.fname);

        ok = ((fno.fattrib & AM_DIR) ? sd_rmdir(path) : f_unlink(path)) == FR_OK;

        path[pathlen] = '\0';
    }

#if defined(__MSP432E401Y__) || defined(ESP_PLATFORM)
    f_closedir(&dir);
#endif

    return ok && f_unlink(path) == FR_OK;
}

static const char *sdcard_handler (http_request_t *request)
{
    char path[100];
    char filename[100], fullname[100];
    char action[20], status[sizeof(filename) + 50];

//    if(!is_authorized(request, WebUIAuth_User))
//        return ESP_OK;

    *status = '\0';
    *path = '\0';

    http_get_param_value(request, "path", path, sizeof(path));
    http_get_param_value(request, "filename", filename, sizeof(filename));
    http_get_param_value(request, "action", action, sizeof(action));

    struct fs_file *file = fs_create();

    if(*action && *filename) {

        FILINFO file;

//        char *fullname = ((file_server_data_t *)req->user_ctx)->scratch;

        strcat(strcpy(fullname, path), filename);

        switch(strlookup(action, "delete,createdir,deletedir", ',')) {

            case 0: // delete
                if(f_stat(fullname, &file) == FR_OK) {
                    if(!(file.fattrib & AM_DIR) && f_unlink(fullname) == FR_OK)
                        sprintf(status, "%s deleted", filename);
                    else
                        sprintf(status, "Cannot delete %s!", filename);
                } else
                    sprintf(status, "%s does not exist!", filename);
                break;

            case 1: // createdir
                if(f_stat(fullname, &file) != FR_OK) {
                    if(f_mkdir(fullname) == FR_OK)
                        sprintf(status, "%s created", filename);
                    else
                        sprintf(status, "Cannot create %s!", filename);
                } else
                    sprintf(status, "%s already exists!", filename);
                break;

            case 2: // deletedir
                if(strlen(fullname) == 1)
                    strcpy(status, "Cannot delete root directory!");
                else if(f_stat(fullname, &file) == FR_OK) {
                    if(sd_rmdir(fullname))
                        sprintf(status, "%s deleted", filename);
                    else
                        sprintf(status, "Error deleting %s!", filename);
                } else
                    sprintf(status, "%s does not exist!", filename);
                break;

            default:
                sprintf(status, "Invalid action \"%s\" for %s!", action, filename);
                break;
        }
    }

    if(*path == '\0')
        strcpy(path, "/");

    if(!sd_ls(request, path, status)) {
        http_set_response_status(request, "500 Internal server error");
        hal.stream.write("Failed to generate response");
    }

    fs_close(file);

    return file_is_json ? "cgi:qry.json" : "cgi:qry.txt";
}

static const char *sdcard_download_handler (http_request_t *request)
{
    static char path[100];

    strcpy(path, ":");
    urldecode(path + 1, http_get_uri(request));

    return path;
}

err_t sdcard_post_receive_data (http_request_t *request, struct pbuf *p)
{
    struct pbuf *q = p;

    http_upload_chunk(request, p->payload, p->len);

    while((q = q->next))
        http_upload_chunk(request, q->payload, q->len);

    httpd_free_pbuf(request, p);

    return ERR_OK;
}

void sdcard_post_finished (http_request_t *request, char *response_uri, u16_t response_uri_len)
{
    struct fs_file *file = fs_create();

    file_upload_t *upload = (file_upload_t *)request->private_data;

    if(upload)
        strncpy(response_uri, upload->path ? upload->path : "/", response_uri_len);

    if(*response_uri == '\0')
        strcpy(response_uri, "/");

    sd_ls(request, response_uri, "ok");

    fs_close(file);

    if(request->on_request_completed) {
        request->on_request_completed(request->private_data);
        request->private_data = NULL;
        request->on_request_completed = NULL;
    }

    strcpy(response_uri, "cgi:qry.json");
}

static const char *sdcard_upload_handler (http_request_t *request)
{
    int len;
    bool ok;
    char ct[200], *boundary;

    if((len = http_get_header_value_len (request, "Content-Type")) >= 0) {
        http_get_header_value (request, "Content-Type", ct, len);
        if((ok = (boundary = strstr(ct, "boundary=")))) {
            boundary += strlen("boundary=");
            ok = http_upload_start(request, boundary, true);
        }
    }

    request->post_receive_data = sdcard_post_receive_data;
    request->post_finished = sdcard_post_finished;

    return NULL;
}

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

static ip_addr_t *get_ipaddress (http_request_t *request)
{
    return &((http_state_t *)(request->handle))->pcb->remote_ip;
}

static webui_auth_level_t check_authenticated (ip_addr_t *ip, const session_id_t *session_id)
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
            if (memcmp(ip, &current->ip, sizeof(ip_addr_t)) == 0 && memcmp(session_id, current->session_id, sizeof(session_id_t)) == 0) {
                current->last_access = now;
                level = current->level;
            }
            previous = current;
            current = current->next;
        }
    }

    return level;
}

static session_id_t *create_session_id (ip_addr_t *ip, uint16_t port)
{
    static session_id_t session_id;

    uint32_t addr;

    memcpy(&addr, ip, sizeof(ip_addr_t));

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

static webui_auth_level_t get_auth_level (http_request_t *req)
{
    session_id_t session_id;
    webui_auth_level_t auth_level = WebUIAuth_None;

    if(get_session_id(req, &session_id))
        auth_level = check_authenticated(get_ipaddress(req), &session_id);

    return auth_level;
}

#endif

static char *authleveltostr (webui_auth_level_t level)
{
    return level == WebUIAuth_None ? "???" : level == WebUIAuth_Guest ? "guest" : level == WebUIAuth_User ? "user" : "admin";
}

static const char *login_handler (http_request_t *request)
{
    bool ok = false;
    char msg[40] = "Ok";
    webui_auth_level_t auth_level = WebUIAuth_None;

#if WEBUI_AUTH_ENABLE

    user_id_t user;
    password_t password;
    char cookie[64];
    uint32_t status = 200;

    if(http_get_param_count(request)) {

        if(http_get_param_value(request, "DISCONNECT", password, sizeof(password))) {
            unlink_session(request);
            auth_level = WebUIAuth_None;
            http_set_response_header(request, "Set-Cookie", strcat(strcpy(cookie, COOKIEPREFIX), "; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT"));

        } else if(http_get_param_value(request, "SUBMIT", password, sizeof(password))) {

             if(http_get_param_value(request, "NEWPASSWORD", password, sizeof(password))) {

                strcpy(user, authleveltostr((auth_level = get_auth_level(request))));

                // TODO: validation against original password needed?

                if(*user && is_valid_password(password)) {

                    switch(strlookup(user, "user,admin", ',')) {

                        case 0:
                            if(settings_store_setting(Setting_UserPassword, password) != Status_OK) {
                                status = 401;
                                strcpy(msg, "Error: Cannot apply changes");
                            }
                            break;

                        case 1:
    //                                ESP_LOGI("newp", "admin");
                            if(settings_store_setting(Setting_AdminPassword, password) != Status_OK) {
    //                                    ESP_LOGI("newp", "admin failed");
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

            } else {

                http_get_param_value(request, "USER", user, sizeof(user));
                http_get_param_value(request, "PASSWORD", password, sizeof(password));

                if(*user) {

                    auth_level = WebUIAuth_Guest;

                    switch(strlookup(user, "user,admin", ',')) {

                        case 0:
                            if(strcmp(password, webui.user_password)) {
                                status = 401;
                                strcpy(msg, "Error: Incorrect password");
                            } else
                                auth_level = WebUIAuth_User;
                            break;

                        case 1:
                            if(strcmp(password, webui.admin_password)) {
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
            }
        } else {
            status = 500;
            strcpy(msg, "Error: Missing data");
        }
    }

    http_set_response_header(request, "Cache-Control", "no-cache");

    webui_auth_level_t current_level = get_auth_level(request);

    if(auth_level != current_level) {

        unlink_session(request);

        if(auth_level != WebUIAuth_None) {

            webui_auth_t *session;

            if((session = malloc(sizeof(webui_auth_t)))) {
                memset(session, 0, sizeof(webui_auth_t));
                memcpy(&session->ip, get_ipaddress(request), sizeof(ip_addr_t));
                memcpy(session->session_id, create_session_id(&session->ip, ((http_state_t *)(request->handle))->pcb->remote_port), sizeof(session_id_t));
                session->level = auth_level;
                strcpy(session->user_id, user);
                session->last_access = hal.get_elapsed_ticks();
                session->next = sessions;
                sessions = session;
            }

            http_set_response_header(request, "Set-Cookie", strcat(strcat(strcpy(cookie, COOKIEPREFIX), session->session_id), "; path=/"));
        }
    }

    if(status != 200) {
        char paranoia[50];
        sprintf(paranoia, "%d %s", (int)status, msg);
        http_set_response_status(request, paranoia);
    }

#endif

    cJSON *root;

    if((root = cJSON_CreateObject())) {

        ok = cJSON_AddStringToObject(root, "status", msg) != NULL;
        ok &= cJSON_AddStringToObject(root, "authentication_lvl", authleveltostr(auth_level)) != NULL;

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

#if WEBUI_AUTH_ENABLE

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

static setting_details_t *on_get_settings (void)
{
    return &details;
}

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
        hal.stream.write("[PLUGIN:WebUI v0.01]" ASCII_EOL);
}

static bool webui_setup (settings_t *settings)
{
    bool ok;

    if((ok = driver_setup(settings)))
        sdcard_getfs(); // Mounts SD card if not already mounted

    return ok;
}

void webui_init (void)
{

#if WEBUI_AUTH_ENABLE
    if((nvs_address = nvs_alloc(sizeof(webui_settings_t)))) {
        details.on_get_settings = grbl.on_get_settings;
        grbl.on_get_settings = on_get_settings;
    }
#endif

    driver_setup = hal.driver_setup;
    hal.driver_setup = webui_setup;

    driver_reset = hal.driver_reset;
    hal.driver_reset = webui_reset;

    on_report_options = grbl.on_report_options;
    grbl.on_report_options = webui_options;

    on_stream_changed = grbl.on_stream_changed;
    grbl.on_stream_changed = stream_changed;

    static const httpd_uri_handler_t cgi[] = {
        { .uri = "/command",  .method =  HTTP_Get,  .handler = command },
        { .uri = "/upload",   .method =  HTTP_Get,  .handler = sdcard_handler },
        { .uri = "/SD/*",     .method =  HTTP_Get,  .handler = sdcard_download_handler },
        { .uri = "/sdcard/*", .method =  HTTP_Get,  .handler = sdcard_download_handler },
        { .uri = "/login",    .method =  HTTP_Get,  .handler = login_handler },
        { .uri = "/upload",   .method =  HTTP_Post, .handler = sdcard_upload_handler }
    };

    httpd_register_uri_handlers(cgi, sizeof(cgi) / sizeof(httpd_uri_handler_t));
}

#endif
