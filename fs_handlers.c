/*
  fs_handlers.c - An embedded CNC Controller with rs274/ngc (g-code) support

  WebUI backend - file handling

  Part of grblHAL

  Copyright (c) 2020-2023 Terje Io

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

#if WEBUI_ENABLE

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "../networking/httpd.h"
#include "../networking/http_upload.h"
#include "../networking/utils.h"
#include "../networking/strutils.h"
#include "../networking/cJSON.h"

#include "grbl/vfs.h"

static bool file_is_json = false;

static void data_is_json (void)
{
    file_is_json = true;
}

// add file to the JSON response array
static bool add_file (cJSON *files, char *path, vfs_dirent_t *file, time_t *mtime)
{
    bool ok;

    cJSON *fileinfo;

    if((ok = (fileinfo = cJSON_CreateObject()) != NULL)) {

        ok = !!cJSON_AddStringToObject(fileinfo, "name", file->name);
#if WEBUI_ENABLE != 2
        if(mtime)
            ok &= !!cJSON_AddStringToObject(fileinfo, "time", strtoisodt(gmtime(mtime)));
#else
        ok &= !!cJSON_AddStringToObject(fileinfo, "datetime", "");
        ok &= !!cJSON_AddStringToObject(fileinfo, "shortname", file->name);
#endif
        if(file->st_mode.directory)
            ok &= !!cJSON_AddNumberToObject(fileinfo, "size", -1.0);
        else
            ok &= !!cJSON_AddStringToObject(fileinfo, "size", btoa(file->size));
    }

    return ok && cJSON_AddItemToArray(files, fileinfo);
}

static char *get_fullpath (char *path, char *filename)
{
    static char fullpath[255];

    return strcat(strcat(strcpy(fullpath, vfs_fixpath(path)), "/"), filename);
}

static int sd_scan_dir (cJSON *files, char *path, uint_fast8_t depth)
{
    int res = 0;
    bool subdirs = false;
    vfs_dir_t *dir;
    vfs_dirent_t *dirent;
#if WEBUI_ENABLE != 2
    vfs_stat_t st;
#endif

    if((dir = vfs_opendir(path)) == NULL)
        return vfs_errno;

   // Pass 1: Scan files
    while(true) {

        if((dirent = vfs_readdir(dir)) == NULL)
            break;

        subdirs |= dirent->st_mode.directory;

        if(!dirent->st_mode.directory) {
#if WEBUI_ENABLE != 2
            int res = vfs_stat(get_fullpath(path, dirent->name), &st);
  #if ESP_PLATFORM
            add_file(files, path, dirent, res == 0 ? &st.st_mtim : NULL);
  #else
            add_file(files, path, dirent, res == 0 ? &st.st_mtime : NULL);
  #endif
#else
            add_file(files, path, dirent, NULL);
#endif
        }
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
            add_file(files, path, dirent, NULL);
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

bool fs_ls (cJSON *root, char *path, char *status, vfs_drive_t *drive)
{
    bool ok;
    cJSON *files = NULL;

    if((ok = (root && (files = cJSON_AddArrayToObject(root, "files"))))) {

        vfs_fixpath(path);
        sd_scan_dir(files, path, 1);

        cJSON_AddStringToObject(root, "path", path);

        vfs_free_t *mount;

        if(drive)
            mount = vfs_drive_getfree(drive);
        else
            mount = vfs_fgetfree(path);

        if(mount) {
            uint32_t pct_used = (mount->used * 100) / mount->size;
            ok &= !!cJSON_AddStringToObject(root, "total", btoa(mount->size));
            ok &= !!cJSON_AddStringToObject(root, "used", btoa(mount->used));
            ok &= !!cJSON_AddStringToObject(root, "occupation", uitoa(pct_used == 0 ? 1 : pct_used));
        }
        if(status) {
            ok &= !!cJSON_AddStringToObject(root, "mode", "direct");
            ok &= !!cJSON_AddStringToObject(root, "status", status);
        }
    }

    return ok;
}

static bool _fs_ls (void *request, char *path, char *status, vfs_file_t *file, vfs_drive_t *drive)
{
    bool ok;
    cJSON *root = cJSON_CreateObject();

    if((ok = root && fs_ls(root, path, status, drive))) {

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

const char *fs_action_handler (http_request_t *request, vfs_drive_t *drive)
{
    bool ok = false;
    char path[100], filename[100], *fullname;
    char action[20], status[sizeof(filename) + 50], quiet[4];
    uint_fast16_t pathlen;

    if(drive == NULL) {
        http_set_response_status(request, "400 Bad Request");
        return NULL;
    }

//    if(!is_authorized(request, WebUIAuth_User))
//        return ESP_OK;

    *status = *path = '\0';

    http_get_param_value(request, "path", filename, sizeof(filename));
    if(strncmp(filename, drive->path, strlen(drive->path)))
        strcpy(path, drive->path);
    else
        strcpy(path, "/");

    strcat(path, *filename == '/' ? filename + 1 : filename);

    http_get_param_value(request, "filename", filename, sizeof(filename));
    http_get_param_value(request, "action", action, sizeof(action));
    http_get_param_value(request, "quiet", quiet, sizeof(quiet));
 
    pathlen = strlen(path);
    if(pathlen > 1 && path[pathlen - 1] != '/') {
        path[pathlen] = '/';
        path[pathlen + 1] = '\0';
    }

    vfs_file_t *file = vfs_open("/ram/qry.json", "w");

    if(*action && *filename) {

        vfs_stat_t file;

//        char *fullname = ((file_server_data_t *)req->user_ctx)->scratch;

        fullname = get_fullpath(path, filename);
/*
        if(strlen(drive->path) > 1 || *drive->path != '/')
            strcat(strcat(strcpy(fullname, drive->path), "/"), filename);
        else
            strcat(strcpy(fullname, path), filename);
*/
        switch(strlookup(action, "delete,createdir,deletedir,list", ',')) {

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
                    if(vfs_rmdir(fullname) == 0)
                        sprintf(status, "%s deleted", filename);
                    else
                        sprintf(status, "Error deleting %s!", filename);
                } else
                    sprintf(status, "%s does not exist!", filename);
                break;

            case 3: // list - do nothing here
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

    ok = *quiet == 'y' || _fs_ls(request, path, status, file, drive);

    if(!ok) {
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

const char *fs_download_handler (http_request_t *request, vfs_drive_t *drive)
{
    static char path[256] = "";

    if(drive == NULL) {
        http_set_response_status(request, "404 Not Found");
        return NULL;
    }

    if(strlen(drive->path) > 1 || *drive->path != '/')
        strcat(strcpy(path, drive->path), "/");

    return strcat(path, http_get_uri(request));
}

static err_t fs_post_receive_data (http_request_t *request, struct pbuf *p)
{
    struct pbuf *q = p;

    http_upload_chunk(request, p->payload, p->len);

    while((q = q->next))
        http_upload_chunk(request, q->payload, q->len);

    httpd_free_pbuf(request, p);

    return ERR_OK;
}

static void fs_post_finished (http_request_t *request, char *response_uri, u16_t response_uri_len)
{
    vfs_drive_t *drive = NULL;
    vfs_file_t *file = vfs_open("/ram/qry.json", "w");
    file_upload_t *upload = (file_upload_t *)request->private_data;

    if(upload) {

        strncpy(response_uri, upload->path ? upload->path : "/", response_uri_len);

        char *s;
        if((s = strrchr(upload->filename, '/')))
            *(++s) = '\0';

        drive = vfs_get_drive(upload->filename);
    }

    if(*response_uri == '\0')
        strcpy(response_uri, "/");

    _fs_ls(request, upload ? upload->filename : response_uri, "ok", file, drive);

    vfs_close(file);

    if(request->on_request_completed) {
        request->on_request_completed(request->private_data);
        request->private_data = NULL;
        request->on_request_completed = NULL;
    }

    strcpy(response_uri, "/ram/qry.json");
}

static void fs_on_upload_name_parsed (char *name, void *data)
{
    char *drive_path = (char *)data;

    size_t len = strlen(name), plen = strlen(drive_path);
    if(!strncmp(name, drive_path, plen))
        plen = 0;
    else if(*name == '/')
        plen--;

    if(plen && len + plen <= HTTP_UPLOAD_MAX_PATHLENGTH) {
        memmove(name + plen, name, len + 1);
        memcpy(name, drive_path, plen);
    }
}

const char *fs_upload_handler (http_request_t *request, vfs_drive_t *drive)
{
    static char drive_path[32];

    int len;
    char ct[200], *boundary;
    file_upload_t *upload = NULL;

    if((len = http_get_header_value_len (request, "Content-Type")) >= 0) {
        http_get_header_value (request, "Content-Type", ct, len);
        if((boundary = strstr(ct, "boundary="))) {
            boundary += strlen("boundary=");
            upload = http_upload_start(request, boundary, true);
            if(upload && drive) {
                strcpy(drive_path, drive->path);
                http_upload_on_filename_parsed(upload, fs_on_upload_name_parsed, drive_path);
            }
        }
    }

    if(upload) {
        request->post_receive_data = fs_post_receive_data;
        request->post_finished = fs_post_finished;
    } else
        http_set_response_status(request, "400 Bad Request");

    return NULL;
}

vfs_drive_t *fs_get_root_drive (void)
{
    static vfs_drive_t root;

    vfs_drives_t *dh;
    vfs_drive_t *drive = NULL;

    if((dh = vfs_drives_open()))
    {
        while((drive = vfs_drives_read(dh, true))) {
            if(!strcmp(drive->name, "/")) {
                memcpy(&root, drive, sizeof(vfs_drive_t));
                break;
            }
        }
        vfs_drives_close(dh);
    }

    return drive ? &root : NULL;
}

vfs_drive_t *fs_get_sd_drive (void)
{
    static vfs_drive_t sd;

    vfs_drives_t *dh;
    vfs_drive_t *drive = NULL;

    if((dh = vfs_drives_open()))
    {
        while((drive = vfs_drives_read(dh, false))) {
            if(drive->removable) {
                memcpy(&sd, drive, sizeof(vfs_drive_t));
                break;
            }
        }
        vfs_drives_close(dh);
    }

    return drive ? &sd : NULL;
}

vfs_drive_t *fs_get_flash_drive (bool add_hidden)
{
    static vfs_drive_t flash;

    vfs_drives_t *dh;
    vfs_drive_t *drive = NULL;

    if((dh = vfs_drives_open()))
    {
        while((drive = vfs_drives_read(dh, add_hidden))) {
            if(!(drive->removable || drive->mode.read_only)) {
                memcpy(&flash, drive, sizeof(vfs_drive_t));
                break;
            } else
                drive = NULL;
        }
        vfs_drives_close(dh);
    }

    return drive ? &flash : NULL;
}

#endif // WEBUI_ENABLE
