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

#include "../networking/websocketd.h"
#include "../networking/utils.h"
#include "../networking/strutils.h"
#include "../networking/cJSON.h"
//#include "../sdcard/sdcard.h"
#include "grbl/vfs.h"
#include "./sdcard.h"


static bool file_is_json = false;

static void data_is_json (void)
{
    file_is_json = true;
}

// add file to the JSON response array
static bool add_file (cJSON *files, char *path, vfs_dirent_t *file)
{
    bool ok;

    cJSON *fileinfo;

    if((ok = (fileinfo = cJSON_CreateObject()) != NULL))
    {
        ok = !!cJSON_AddStringToObject(fileinfo, "name", file->name);
        ok &= !!cJSON_AddStringToObject(fileinfo, "shortname", file->name);
        ok &= !!cJSON_AddStringToObject(fileinfo, "datetime", "");
        if(file->st_mode.directory)
            ok &= !!cJSON_AddNumberToObject(fileinfo, "size", -1.0);
        else
            ok &= !!cJSON_AddStringToObject(fileinfo, "size", btoa(file->size));
    }

    return ok && cJSON_AddItemToArray(files, fileinfo);
}

static int sd_scan_dir (cJSON *files, char *path, uint_fast8_t depth)
{
    int res = 0;
    vfs_dir_t *dir;
    vfs_dirent_t *dirent;

    bool subdirs = false;

   if((dir = vfs_opendir(path)) == NULL)
        return vfs_errno;

   // Pass 1: Scan files
    while(true) {

        if((dirent = vfs_readdir(dir)) == NULL)
            break;

        subdirs |= dirent->st_mode.directory;

        if(!dirent->st_mode.directory)
            add_file(files, path, dirent);
    }

    vfs_closedir(dir);
    dir = NULL;

    if((subdirs = (subdirs && depth)))
        subdirs = (dir = vfs_opendir(path)) != NULL;

    // Pass 2: Scan directories
    while(subdirs) {

        if((dirent = vfs_readdir(dir)) == NULL)
            break;

        if(dirent->st_mode.directory) {

            size_t pathlen = strlen(path);
//          if(pathlen + strlen(get_name(&fno)) > (MAX_PATHLEN - 1))
                //break;
            add_file(files, path, dirent);
            if(depth > 1) {
                sprintf(&path[pathlen], "/%s", dirent->name);
                if((res = sd_scan_dir(files, path, depth - 1)) != 0)
                    break;
                path[pathlen] = '\0';
            }
        }
    }

    if(dir)
        vfs_closedir(dir);

    return res;
}

static bool sd_ls (void *request, char *path, char *status, vfs_file_t *file)
{
    bool ok;
    uint_fast16_t pathlen = strlen(path);
    cJSON *root = cJSON_CreateObject(), *files = NULL;

    if((ok = (root && (files = cJSON_AddArrayToObject(root, "files"))))) {

        if(pathlen > 1 && path[pathlen - 1] == '/')
            path[pathlen - 1] = '\0';

        sd_scan_dir(files, path, 1);

        cJSON_AddStringToObject(root, "path", path);

        vfs_free_t *mount = vfs_fgetfree(path);

        if(mount) {
            uint32_t pct_used = (mount->used * 100) / mount->size;
            ok &= !!cJSON_AddStringToObject(root, "total", btoa(mount->size));
            ok &= !!cJSON_AddStringToObject(root, "used", btoa(mount->used));
            ok &= !!cJSON_AddStringToObject(root, "occupation", uitoa(pct_used == 0 ? 1 : pct_used));
        }
        ok &= !!cJSON_AddStringToObject(root, "mode", "direct");
        ok &= !!cJSON_AddStringToObject(root, "status", status);

        char *resp = cJSON_PrintUnformatted(root);

        data_is_json();

        vfs_puts(resp, file);

        free(resp);

        http_set_response_header(request, "Cache-Control", "no-cache");
    }

    if(root)
        cJSON_Delete(root);

    return ok;
}
/* TODO: mode to vfs?
static bool sd_rmdir (char *path)
{
    bool ok = true;

#if defined(ESP_PLATFORM)
    FF_DIR dir;
#else
    vfs_dir_t *dir;
#endif
    vfs_dirent_t *fno;

#if _USE_LFN
    static TCHAR lfn[_MAX_LFN + 1];   // Buffer to store the LFN
    fno.lfname = lfn;
    fno.lfsize = sizeof(lfn);
#endif

   if((dir = vfs_opendir(path)) == NULL)
        return false;

    size_t pathlen = strlen(path);

    while(ok) {

        if((fno = vfs_readdir(dir)) == NULL || *fno->name == '\0')
            break;

        strcat(strcat(path, "/"), fno->name);

        ok = ((fno.fattrib & AM_DIR) ? sd_rmdir(path) : vfs_unlink(path)) == 0;

        path[pathlen] = '\0';
    }

#if defined(__MSP432E401Y__) || defined(ESP_PLATFORM)
    f_closedir(&dir);
#endif

    return ok && f_unlink(path) == FR_OK;
}
*/

const char *sdcard_handler (http_request_t *request)
{
    bool ok = false;
    char path[100];
    char filename[100], fullname[100];
    char action[20], status[sizeof(filename) + 50];

//    if(!is_authorized(request, WebUIAuth_User))
//        return ESP_OK;

    *status = *path = '\0';

    http_get_param_value(request, "path", path, sizeof(path));
    http_get_param_value(request, "filename", filename, sizeof(filename));
    http_get_param_value(request, "action", action, sizeof(action));

    vfs_file_t *file = vfs_open("/ram/qry.json", "w");

    if(*action && *filename) {

        vfs_stat_t file;
        uint_fast16_t pathlen = strlen(path);

        if(pathlen > 1 && path[pathlen - 1] != '/') {
            path[pathlen] = '/';
            path[pathlen + 1] = '\0';
        }

//        char *fullname = ((file_server_data_t *)req->user_ctx)->scratch;

        strcat(strcpy(fullname, path), filename);

        switch(strlookup(action, "delete,createdir,deletedir", ',')) {

            case 0: // delete
                if(vfs_stat(fullname, &file) == 0) {
                    if(!(file.st_mode.directory) && vfs_unlink(fullname) == 0)
                        sprintf(status, "%s deleted", filename);
                    else
                        sprintf(status, "Cannot delete %s!", filename);
                } else
                    sprintf(status, "%s does not exist!", filename);
                break;

            case 1: // createdir
                if(vfs_stat(fullname, &file) != 0) {
                    if(vfs_mkdir(fullname) == 0)
                        sprintf(status, "%s created", filename);
                    else
                        sprintf(status, "Cannot create %s!", filename);
                } else
                    sprintf(status, "%s already exists!", filename);
                break;

            case 2: // deletedir
                if(strlen(fullname) == 1)
                    strcpy(status, "Cannot delete root directory!");
                else if(vfs_stat(fullname, &file) == 0) {
//                    if(sd_rmdir(fullname))
                      if(vfs_rmdir(fullname))
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

    if(*status == '\0')
        strcat(status, "ok");

    if(!(ok = sd_ls(request, path, status, file))) {
        http_set_response_status(request, "500 Internal Server Error");
        vfs_puts("Failed to generate response", file);
    }

#if LWIP_HTTPD_FILE_STATE

    char *fname = (char *)file->state;

    fs_close(file);

    return fname;

#else

    vfs_close(file);

    return "/ram/qry.json";

#endif
}

const char *sdcard_download_handler (http_request_t *request)
{
//    static char path[100];

//    strcpy(path, ":");
//    strcat(http_get_uri(request));

    return http_get_uri(request);
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
    vfs_file_t *file = vfs_open("/ram/qry.json", "w");

    file_upload_t *upload = (file_upload_t *)request->private_data;

    if(upload)
        strncpy(response_uri, upload->path ? upload->path : "/", response_uri_len);

    if(*response_uri == '\0')
        strcpy(response_uri, "/");

    sd_ls(request, response_uri, "ok", file);

    vfs_close(file);

    if(request->on_request_completed) {
        request->on_request_completed(request->private_data);
        request->private_data = NULL;
        request->on_request_completed = NULL;
    }

    strcpy(response_uri, "/ram/qry.json");
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

#endif // WEBUI_ENABLE &&  SDCARD_ENABLE
