/*
  sdcard.c - An embedded CNC Controller with rs274/ngc (g-code) support

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

#ifdef ARDUINO
#include "../driver.h"
#else
#include "driver.h"
#endif

#if WEBUI_ENABLE && SDCARD_ENABLE

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "../networking/urldecode.h"
#include "../networking/websocketd.h"
#include "../networking/utils.h"
#include "../networking/strutils.h"
#include "../networking/cJSON.h"
#include "../sdcard/sdcard.h"
#include "./sdcard.h"

#ifdef ESP_PLATFORM

#include <sys/socket.h>

#include "../web/backend.h"
#include "../esp_webui/server.h"

#define http_get_header_value_len(a,b) httpd_req_get_hdr_value_len(a,b)
#define http_get_header_value(a,b,c,d) httpd_req_get_hdr_value_str(a,b,c,d)
#define http_get_param_value_len(a,b,c,d) http_get_key_value(a,b,c,d)
#define http_set_response_header(a,b,c) httpd_resp_set_hdr(a,b,c)
#define http_set_response_status(a, b) httpd_resp_set_status(a,b)

#else

extern struct fs_file *fs_create (void);
extern int fs_bytes_left (struct fs_file *file);
extern void fs_register_embedded_files (const embedded_file_t **files);
extern void fs_reset (void);
#if LWIP_HTTPD_FILE_STATE
void fs_file_is_json (struct fs_file *file);
#endif

static bool file_is_json = false;

static void data_is_json (void)
{
    file_is_json = true;
}

#endif

// add file to the JSON response array
static bool add_file (cJSON *files, char *path, FILINFO *file)
{
    bool ok;

    cJSON *fileinfo;

    if((ok = (fileinfo = cJSON_CreateObject()) != NULL))
    {
        ok = !!cJSON_AddStringToObject(fileinfo, "name", file->fname);
        ok &= !!cJSON_AddStringToObject(fileinfo, "shortname", file->fname);
        ok &= !!cJSON_AddStringToObject(fileinfo, "datetime", "");
        if(file->fattrib & AM_DIR)
            ok &= !!cJSON_AddNumberToObject(fileinfo, "size", -1.0);
        else
            ok &= !!cJSON_AddStringToObject(fileinfo, "size", btoa(file->fsize));
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
            ok &= !!cJSON_AddStringToObject(root, "total", btoa(tot_sect << 9)); // assuming 512 byte sector size
            ok &= !!cJSON_AddStringToObject(root, "used", btoa(used_sect << 9));
            ok &= !!cJSON_AddStringToObject(root, "occupation", uitoa(pct_used == 0 ? 1 : pct_used));
        }
        ok &= !!cJSON_AddStringToObject(root, "mode", "direct");
        ok &= !!cJSON_AddStringToObject(root, "status", status);

        char *resp = cJSON_PrintUnformatted(root);

#if defined(ESP_PLATFORM)
        httpd_resp_set_hdr(request, "Cache-Control", "no-cache");
        httpd_resp_set_type(request, HTTPD_TYPE_JSON);
        httpd_resp_send(request, resp, strlen(resp));
#else
        data_is_json();

        hal.stream.write(resp);

        free(resp);

        http_set_response_header(request, "Cache-Control", "no-cache");
#endif
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

#ifdef ESP_PLATFORM
esp_err_t sdcard_handler (http_request_t *request)
#else
const char *sdcard_handler (http_request_t *request)
#endif
{
    bool ok = false;
    char path[100];
    char filename[100], fullname[100];
    char action[20], status[sizeof(filename) + 50];

//    if(!is_authorized(request, WebUIAuth_User))
//        return ESP_OK;

    *status = *path = '\0';

#ifdef ESP_PLATFORM

    char *query;
    size_t qlen = httpd_req_get_url_query_len(request);

    if(qlen && (query = malloc(qlen + 1))) {

        httpd_req_get_url_query_str(request, query, qlen);

        http_get_key_value(query, "path", path, sizeof(path));
        http_get_key_value(query, "filename", filename, sizeof(filename));
        http_get_key_value(query, "action", action, sizeof(action));

        free(query);
    }

#else

    http_get_param_value(request, "path", path, sizeof(path));
    http_get_param_value(request, "filename", filename, sizeof(filename));
    http_get_param_value(request, "action", action, sizeof(action));

    struct fs_file *file = fs_create();

#endif


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

    if(!(ok = sd_ls(request, path, status))) {
        http_set_response_status(request, "500 Internal server error");
        hal.stream.write("Failed to generate response");
    }

#ifdef ESP_PLATFORM

    return ok ? ESP_OK : ESP_FAIL;

#else

    char *fname = (char *)file->state;

    fs_close(file);

    return fname;

#endif
}

#ifdef ESP_PLATFORM

esp_err_t sdcard_upload_handler (httpd_req_t *req)
{
    bool ok = false;
    int ret;

//    if(!is_authorized(req, WebUIAuth_User))
//        return ESP_OK;

    char *rqhdr = NULL, *boundary;
    size_t len = httpd_req_get_hdr_value_len(req, "Content-Type");

    if(len) {
        rqhdr = malloc(len + 1);
        httpd_req_get_hdr_value_str(req, "Content-Type", rqhdr, len + 1);

        if((ok = (boundary = strstr(rqhdr, "boundary=")))) {
            boundary += strlen("boundary=");
            ok = http_upload_start(req, boundary, true);
        }
    }

    fs_path_t path;
    char *scratch = ((file_server_data_t *)req->user_ctx)->scratch;
    file_upload_t *upload = (file_upload_t *)req->sess_ctx;

    *path = '\0';

    if (ok) do { // Process received data

        if ((ret = httpd_req_recv(req, scratch, sizeof(fs_scratch_t))) <= 0) {
            ok = false;
            if (ret == HTTPD_SOCK_ERR_TIMEOUT)
                httpd_resp_send_408(req);
            break;
        }

        http_upload_chunk(req, scratch, (size_t)ret);

        if(*path == '\0' && *upload->path)
            strcpy(path, upload->path);

    } while(upload->state != Upload_Complete);

    if(*path == '\0') // in case something failed...
        strcpy(path, "/");

    if(!(ok && sd_ls(req, path, "ok")))
        httpd_resp_send_err(req, 400, "Upload failed"); // or did it?

    if(req->sess_ctx && req->free_ctx) {
        req->free_ctx(req->sess_ctx);
        req->sess_ctx = NULL;
    }

    hal.stream.write(ok ? "[MSG:Upload ok]\r\n" : "[MSG:Upload failed]\r\n");

    if(rqhdr)
        free(rqhdr);

    return ok ? ESP_OK : ESP_FAIL;
}

#else

const char *sdcard_download_handler (http_request_t *request)
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

const char *sdcard_upload_handler (http_request_t *request)
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

#endif // WEBUI_ENABLE &&  SDCARD_ENABLE
