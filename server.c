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

#include "../networking/urldecode.h"
#include "../networking/websocketd.h"
#include "../networking/httpd.h"
#include "../networking/utils.h"
#include "../networking/strutils.h"
#include "../networking/cJSON.h"
#include "../networking/http_upload.h"
#include "../sdcard/sdcard.h"

#include "commands.h"

#if WEBUI_INFLASH
#include "filedata.h"
#endif
#if WEBUI_AUTH_ENABLE
#include "login.h"
#endif

extern struct fs_file *fs_create (void);
extern int fs_bytes_left (struct fs_file *file);
extern void fs_register_embedded_files (const embedded_file_t **files);

void fs_reset (void);

static bool file_is_json = false;
static driver_setup_ptr driver_setup;
static driver_reset_ptr driver_reset;
static on_stream_changed_ptr on_stream_changed;
static on_report_options_ptr on_report_options;
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
    uint_fast16_t pathlen = strlen(path);
    cJSON *root = cJSON_CreateObject(), *files = NULL;

    if((ok = (root && (files = cJSON_AddArrayToObject(root, "files"))))) {

        if(pathlen > 1 && path[pathlen - 1] == '/')
            path[pathlen - 1] = '\0';

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
        uint_fast16_t pathlen = strlen(path);

        if(pathlen > 1 && path[pathlen - 1] != '/') {
            path[pathlen] = '/';
            path[pathlen + 1] = '\0';
        }

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

    static const httpd_uri_handler_t cgi[] = {
        { .uri = "/command",  .method =  HTTP_Get,  .handler = command },
        { .uri = "/upload",   .method =  HTTP_Get,  .handler = sdcard_handler },
        { .uri = "/sdfiles",  .method =  HTTP_Get,  .handler = sdcard_handler },
        { .uri = "/SD/*",     .method =  HTTP_Get,  .handler = sdcard_download_handler },
        { .uri = "/sdcard/*", .method =  HTTP_Get,  .handler = sdcard_download_handler },
        { .uri = "/login",    .method =  HTTP_Get,  .handler = login_handler_get },
#if WEBUI_AUTH_ENABLE
        { .uri = "/login",    .method =  HTTP_Post, .handler = login_handler_post },
#endif
        { .uri = "/upload",   .method =  HTTP_Post, .handler = sdcard_upload_handler },
        { .uri = "/sdfiles",  .method =  HTTP_Post, .handler = sdcard_upload_handler },
        { .uri = "/files",    .method =  HTTP_Post, .handler = spiffs_upload_handler }
    };

    httpd_register_uri_handlers(cgi, sizeof(cgi) / sizeof(httpd_uri_handler_t));

#if WEBUI_INFLASH
    fs_register_embedded_files(ro_files);
#endif
}

#endif
