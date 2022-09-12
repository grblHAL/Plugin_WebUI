/*
  commands_v3.c - An embedded CNC Controller with rs274/ngc (g-code) support

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

#include "driver.h"

#if WEBUI_ENABLE == 1 || WEBUI_ENABLE == 3

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#include "../networking/networking.h"
#include "../networking/utils.h"
#include "../networking/strutils.h"
#include "../networking/cJSON.h"

#include "args.h"
#include "webui.h"
#include "fs_handlers.h"

#include "grbl/vfs.h"
#include "grbl/report.h"
#include "grbl/state_machine.h"
#include "grbl/motion_control.h"

#include "sdcard/sdcard.h"

#if WIFI_ENABLE
#include "wifi.h"
#endif

//#include "flashfs.h"

#define WEBUI_EOL "\n"
#define FIRMWARE_ID "80"
#define FIRMWARE_TARGET "grblHAL"

extern void data_is_json (void);

typedef enum {
    WebUIType_IPAddress = 'A',
    WebUIType_Integer = 'I',
    WebUIType_Float = 'F',
    WebUIType_String = 'S',
    WebUIType_Byte = 'B',
    WebUIType_Bitmask = 'M',
    WebUIType_XBitmask = 'X'
} webui_stype_t;

typedef struct {
    setting_id_t id;
    int8_t bit;
} webui_setting_map_t;

typedef struct {
    webui_auth_level_t read;
    webui_auth_level_t execute;
} webui_auth_required_t;

typedef struct webui_cmd_binding {
    uint_fast16_t id;
    status_code_t (*handler)(const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
    webui_auth_required_t auth;
    const char *help;
    webui_setting_map_t setting;
} webui_cmd_binding_t;

//typedef status_code_t (*webui_command_handler_ptr)(const webui_cmd_binding_t *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);

static status_code_t list_commands (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
static status_code_t esp_setting (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
static status_code_t get_settings (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
static status_code_t set_setting (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
static status_code_t get_set_time (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
static status_code_t get_system_status (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
static status_code_t get_firmware_spec (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
static status_code_t get_current_ip (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
static status_code_t set_cpu_state (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
static status_code_t show_pins (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
static status_code_t handle_job_status (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
static status_code_t get_sd_status (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
static status_code_t global_fs_ls (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
static status_code_t global_fs_action (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
static status_code_t flashfs_ls (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
static status_code_t flashfs_action (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
static status_code_t sdcard_ls (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
static status_code_t sdcard_action (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
static status_code_t sdcard_format (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
#if WIFI_ENABLE
static status_code_t get_ap_list (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
#endif
static status_code_t flash_read_file (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
static status_code_t flash_format (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);

static const webui_cmd_binding_t webui_commands[] = {
    { 0,   list_commands,      { WebUIAuth_Guest, WebUIAuth_None},  "(<command id>) - display this help" },
// Settings commands
#if WIFI_ENABLE
    { 100, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "(<ssid>) - display/set STA SSID", { Setting_WiFi_STA_SSID, -1 } },
    { 101, esp_setting,        { WebUIAuth_Admin, WebUIAuth_Admin}, "<password> - set STA password", { Setting_WiFi_STA_Password, -1 } },
    { 102, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "(<DHCP|STATIC>) - display/set STA IP mode", { Setting_IpMode, -1 } },
    { 103, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "(IP=<ipv4> MSK=<ipv4> GW=<ipv4>) - display/set STA IP/Mask/GW", { 0, -1 } },
    { 105, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "(<ssid>) - display/set AP SSID", { Setting_WiFi_AP_SSID, -1 } },
    { 106, esp_setting,        { WebUIAuth_Admin, WebUIAuth_Admin}, "<password> - set AP password", { Setting_WiFi_AP_Password, -1 } },
    { 107, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "(<ipv4>) - display/set AP IP", { Setting_IpAddress2, -1 } },
    { 108, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "(<channel>) - display/set AP channel", { Setting_Wifi_AP_Channel, -1 } },
//  { 110, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "<BT|WIFI-STA|WIFI-AP|WIFI-SETUP|ETH-STA|OFF> - display/set radio state", { Setting_WifiMode, -1 } },
#elif ETHERNET_ENABLE
    { 102, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "(<DHCP|STATIC>) - display/set Ethernet IP mode", { Setting_IpMode, -1 } },
    { 103, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "(IP=<ipv4> MSK=<ipv4> GW=<ipv4>) - display/set Ethernet IP/Mask/GW", { 0, -1 } },
#endif
#if WIFI_ENABLE || ETHERNET_ENABLE
    { 111, get_current_ip,     { WebUIAuth_Guest, WebUIAuth_Admin}, "- display current IP" },
    { 112, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "(<hostname>) - display/set Hostname", { Setting_Hostname, -1 } },
#if HTTP_ENABLE
    { 120, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "(<ON|OFF>) - display/set HTTP state", { Setting_NetworkServices, 2 } },
    { 121, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "(<port>) - display/set HTTP port", { Setting_HttpPort, -1 } },
#endif
#if TELNET_ENABLE
    { 130, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "(<ON|OFF>) - display/set Telnet state", { Setting_NetworkServices, 0 } },
    { 131, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "(<port>) - display/set Telnet port", { Setting_TelnetPort, -1 } },
#endif
    { 140, get_set_time,       { WebUIAuth_Guest, WebUIAuth_Admin}, "(json=yes) - sync/display/set time"},
#if WEBSOCKET_ENABLE
    { 160, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "(<ON|OFF>) - display/set WebSocket state", { Setting_NetworkServices, 1 } },
    { 161, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "(<port>) - display/set WebSocket port", { Setting_WebSocketPort, -1 } },
#endif
#if FTP_ENABLE
    { 180, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "(<ON|OFF>) - display/set FTP state", { Setting_NetworkServices, 3 } },
    { 181, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "(<port>) - display/set FTP port", { Setting_WebSocketPort, -1 } },
#endif
#endif
#if BLUETOOTH_ENABLE
    { 140, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "??", { Setting_BlueToothServiceName, -1 } },
#endif
// Action commands
    { 200, get_sd_status,      { WebUIAuth_User, WebUIAuth_Admin},  "(json=yes) (<RELEASE|REFRESH>) - display/set SD Card Status" },
    { 220, show_pins,          { WebUIAuth_User, WebUIAuth_Admin},  "(json=yes) (<SNAP>) - show pins" },
    { 400, get_settings,       { WebUIAuth_User, WebUIAuth_Admin},  " - display ESP3D settings in JSON" },
    { 401, set_setting,        { WebUIAuth_Admin, WebUIAuth_Admin}, "P=<setting id> T=<type> V=<value> - set specific setting" },
#if WIFI_ENABLE
    { 410, get_ap_list,        { WebUIAuth_User, WebUIAuth_Admin},  "(json=yes) - display available AP list (limited to 30) in plain/JSON" },
#endif
    { 420, get_system_status,  { WebUIAuth_User, WebUIAuth_Admin},  "(json=yes) - display ESP3D current status in plain/JSON" },
    { 444, set_cpu_state,      { WebUIAuth_Admin, WebUIAuth_Admin}, "<RESET|RESTART> - set ESP3D state" },
    { 700, flash_read_file,    { WebUIAuth_User, WebUIAuth_Admin},  "<filename> - read local filesystem file" },
    { 701, handle_job_status,  { WebUIAuth_Guest, WebUIAuth_Admin}, "(action=<PAUSE|RESUME|ABORT>) - query or control current job" },
    { 710, flash_format,       { WebUIAuth_Admin, WebUIAuth_Admin}, "FORMATFS - format flash filesystem" },
    { 715, sdcard_format,      { WebUIAuth_Admin, WebUIAuth_Admin}, "FORMATFS - format sd filesystem" },
    { 720, flashfs_ls,         { WebUIAuth_Guest, WebUIAuth_Admin}, "<Root> json=<no> pwd=<admin password> - list flash file system" },
    { 730, flashfs_action,     { WebUIAuth_Guest, WebUIAuth_Admin}, "<create|exists|remove|mkdir|rmdir>=<path> (json=no) - action on flash file system" },
    { 740, sdcard_ls,          { WebUIAuth_Guest, WebUIAuth_Admin}, "<Root> json=<no> pwd=<admin password> - list sd file system" },
    { 750, sdcard_action,      { WebUIAuth_Guest, WebUIAuth_Admin}, "<create|exists|remove|mkdir|rmdir>=<path> (json=no) - action on sd file system" },
    { 780, global_fs_ls,       { WebUIAuth_Guest, WebUIAuth_Admin}, "<Root> json=<no> pwd=<admin password> - list global file system" },
    { 790, global_fs_action,   { WebUIAuth_Guest, WebUIAuth_Admin}, "<create|exists|remove|mkdir|rmdir>=<path> (json=no) - action on global file system" },
    { 800, get_firmware_spec,  { WebUIAuth_Guest, WebUIAuth_Guest}, "(json=yes) - display FW Informations in plain/JSON" }
};

static cJSON *json_create_response_hdr (uint_fast16_t cmd, bool array, bool ok, cJSON **data, const char *msg)
{
    bool success;
    cJSON *root = cJSON_CreateObject();

    if((success = root != NULL)) {
        success &= !!cJSON_AddStringToObject(root, "cmd", uitoa((uint32_t)cmd));
        success &= !!cJSON_AddStringToObject(root, "status", ok ? "ok" : "error");
        if(msg)
            success &= !!cJSON_AddStringToObject(root, "data", msg);
        else if(data != NULL)
            success &= !!(*data = (array ? cJSON_AddArrayToObject(root, "data") : cJSON_AddObjectToObject(root, "data")));
        else
            success = false;
    }

    if(!success && root) {
        cJSON_Delete(root);
        root = NULL;
    }

    return root;
}

static bool json_write_response (cJSON *json, vfs_file_t *file)
{
    if(json) {

        char *resp = cJSON_PrintUnformatted(json);

        if(resp) {

            data_is_json();

            vfs_puts(resp, file);

            cJSON_free(resp);
        }

        cJSON_Delete(json);
    }

    return !!json;
}

status_code_t webui_v3_command_handler (uint32_t command, uint_fast16_t argc, char **argv, webui_auth_level_t auth_level, vfs_file_t *file)
{
    bool json;
    status_code_t status = Status_Unhandled;

//  hal.delay_ms(100, NULL);

    webui_trim_arg(&argc, argv, "pwd=");

    json = webui_get_arg(argc, argv, "json=") == NULL || webui_get_bool_arg(argc, argv, "json=");

    webui_trim_arg(&argc, argv, "json");
    webui_trim_arg(&argc, argv, "json=");

    uint32_t i = sizeof(webui_commands) / sizeof(webui_cmd_binding_t);

    while(i) {
        if(webui_commands[--i].id == command) {
#if WEBUI_AUTH_ENABLE
            if(auth_level < (argc == 0 ? webui_commands[i].auth.read : webui_commands[i].auth.execute)) {
                if(json)
                    json_write_response(json_create_response_hdr(webui_commands[i].id, false, true, NULL, "Wrong authentication level"), file);
                else
                    vfs_puts("Wrong authentication level" ASCII_EOL, file);

                status = auth_level < WebUIAuth_User ? Status_AuthenticationRequired : Status_AccessDenied;
            } else
#endif
            status = webui_commands[i].handler(&webui_commands[i], argc, argv, json, file);
            i = 0;
        }
    }

    return status;
}

static status_code_t sys_set_setting (setting_id_t id, char *value)
{
    sys_state_t state = state_get();
    status_code_t retval = Status_OK;

    if(state == STATE_IDLE || (state & (STATE_ALARM|STATE_ESTOP|STATE_CHECK_MODE))) {
        retval = settings_store_setting(id, value);
    } else
        retval = Status_IdleError;

    return retval;
}

static char *get_setting_value (char *data, setting_id_t id)
{
    char *value = NULL;

    const setting_detail_t *setting = setting_get_details(id, NULL);
    if(setting)
        value = setting_get_value(setting, id - setting->id);

    if(value)
        strcpy(data, value);

    return value ? data : NULL;
}

static uint32_t get_int_setting_value (const setting_detail_t *setting, uint_fast16_t offset)
{
    uint32_t value = 0;
    setting_id_t id = (setting_id_t)(setting->id + offset);

    switch(setting->type) {

        case Setting_NonCore:
        case Setting_IsExtended:
        case Setting_IsLegacy:
        case Setting_IsExpanded:
            switch(setting->datatype) {

                case Format_Int8:
                case Format_Bool:
                case Format_Bitfield:
                case Format_XBitfield:
                case Format_AxisMask:
                case Format_RadioButtons:
                    value = *((uint8_t *)(setting->value));
                    break;

                case Format_Int16:
                    value = *((uint16_t *)(setting->value));
                    break;

                case Format_Integer:
                    value = *((uint32_t *)(setting->value));
                    break;

                default:
                    break;
            }
            break;

        case Setting_NonCoreFn:
        case Setting_IsExtendedFn:
        case Setting_IsLegacyFn:
        case Setting_IsExpandedFn:
            switch(setting->datatype) {

                case Format_String:
                case Format_Password:
                case Format_IPv4:
                    break;

                default:
                    value = ((setting_get_int_ptr)(setting->get_value))(id);
                    break;
            }
            break;
    }

    return value;
}

static status_code_t esp_setting (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    bool ok;
    char response[100];
    cJSON *root = NULL;
    status_code_t status = Status_Unhandled;

    if(command->setting.id != 0) { // straight mapping

        const setting_detail_t *setting = setting_get_details(command->setting.id, NULL);
        bool lookup = setting->datatype == Format_RadioButtons;

        if(argc == 0) {

            uint32_t value;
            char buf[100], *svalue;

            if(setting) {
                status = Status_OK;
                value = command->setting.bit == -1 ? get_int_setting_value(setting, 0) : ((get_int_setting_value(setting, 0) & (1 << command->setting.bit)) ? 1 : 0);
                svalue = lookup ? strgetentry(buf, setting->format, value, ',') : (command->setting.bit == -1 ? strcpy(buf, setting_get_value(setting, 0)) : (value ? "ON" : "OFF"));
            }

            if(json) {
                ok = !!(root = json_create_response_hdr(command->id, false, !!setting, NULL, svalue));
            } else {
                if(setting) {
                    status = Status_OK;
                    vfs_puts(strappend(response, 2, svalue, WEBUI_EOL), file);
                }
            }
        } else {

            char *param = argv[0];

            if(command->setting.bit != -1) {
                int32_t mode = strlookup(param, "OFF,ON", ',');
                uint32_t pmask = 1 << command->setting.bit, tmask = get_int_setting_value(setting, 0);
                if(mode >= 0) {
                    if(mode)
                        tmask |= pmask;
                    else
                        tmask ^= pmask;
                    param = uitoa(tmask);
                }
            } else if(lookup) {
                int32_t value = strlookup(param, setting->format, ',');
                if(value != -1)
                    param = uitoa((uint32_t)value);
            }

            status = sys_set_setting(command->setting.id, param);

            if(json)
                root = json_create_response_hdr(command->id, false, status == Status_OK, NULL, status == Status_OK ? "ok" : "Set failed");
        }
    } else switch(command->id) {

        case 103: // GetSetSTA_IP:
            status = Status_OK;
            if(argc == 0) {
                if(json) {

                    cJSON *data;

                    if((ok = !!(root = json_create_response_hdr(command->id, false, true, &data, NULL)))) {

                        const setting_detail_t *setting;

                        if((setting = setting_get_details(Setting_IpAddress, 0)))
                            ok &= !!cJSON_AddStringToObject(data, "ip", setting_get_value(setting, 0));

                        if((setting = setting_get_details(Setting_Gateway, 0)))
                            ok &= !!cJSON_AddStringToObject(data, "gw", setting_get_value(setting, 0));

                        if((setting = setting_get_details(Setting_NetMask, 0)))
                            ok &= !!cJSON_AddStringToObject(data, "msk", setting_get_value(setting, 0));
                    }
                } else {
                    char ip[16], gw[16], mask[16];
                    sprintf(response, "IP:%s, GW:%s, MSK:%s\n", get_setting_value(ip, Setting_IpAddress), get_setting_value(gw, Setting_Gateway), get_setting_value(mask, Setting_NetMask));
                    vfs_puts(response, file);
                }
            } else {
                char *ip;
                bool found = false;
                if((ip = webui_get_arg(argc, argv, "IP=")) && status == Status_OK) {
                    found = true;
                    status = sys_set_setting(Setting_IpAddress, ip);
                }
                if((ip = webui_get_arg(argc, argv, "GW=")) && status == Status_OK) {
                    found = true;
                    status = sys_set_setting(Setting_Gateway, ip);
                }
                if((ip = webui_get_arg(argc, argv, "MSK=")) && status == Status_OK) {
                    found = true;
                    status = sys_set_setting(Setting_NetMask, ip);
                }
                if(!found)
                    status = Status_Unhandled;

                if(json)
                    root = json_create_response_hdr(command->id, false, status == Status_OK, NULL, status == Status_OK ? "ok" : "Set failed");
            }
            break;

        default:
            break;
    }

    if(root)
        json_write_response(root, file);

    if(status != Status_OK && !json)
        vfs_puts("error:setting failure", file);

    return status;
}

// ESP0
static status_code_t list_commands (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    bool ok;
    char buf[200];
    int32_t cmd = -1;
    const webui_cmd_binding_t *cmdp = NULL;
    uint32_t i, n = sizeof(webui_commands) / sizeof(webui_cmd_binding_t);
    cJSON *root = NULL;

    if(!(ok = argc == 0)) {
        cmd = atoi(argv[0]);
        for(i = 0; i < n; i++) {
            if(webui_commands[i].id == cmd) {
                cmdp = &webui_commands[i];
                break;
            }
        }

        if(cmdp == NULL)
            strappend(buf, 2, "This command is not supported: ", argv[0]);
        else
            sprintf(buf, "[ESP%d]%s", cmdp->id, cmdp->help);

        if(json) {

            cJSON *data;

            if((ok = !!(root = json_create_response_hdr(command->id, false, cmdp != NULL, &data, cmdp == NULL ? buf : NULL)))) {
                if(cmdp) {
                    ok &= !!cJSON_AddStringToObject(data, "id", uitoa(cmdp->id));
                    ok &= !!cJSON_AddStringToObject(data, "help", buf);
                }
            }
        } else {
            vfs_puts(buf, file);
            vfs_puts(WEBUI_EOL, file);
        }
    } else if(json) {

        cJSON *data, *msg;

        if((ok = !!(root = json_create_response_hdr(command->id, true, true, &data, NULL)))) {

            for(i = 0; i < n; i++) {
                if((ok = !!(msg = cJSON_CreateObject())))
                {
                    sprintf(buf, "[ESP%d]%s", webui_commands[i].id, webui_commands[i].help);

                    ok &= !!cJSON_AddStringToObject(msg, "id", uitoa(webui_commands[i].id));
                    ok &= !!cJSON_AddStringToObject(msg, "help", buf);

                    if(ok)
                        cJSON_AddItemToArray(data, msg);
                }
            }
        }
    } else {
        vfs_puts("[List of ESP3D commands]" WEBUI_EOL, file);
        for(i = 0; i < n; i++) {
            sprintf(buf, "[ESP%d]%s" WEBUI_EOL, webui_commands[i].id, webui_commands[i].help);
            vfs_puts(buf, file);
        }
    }

    if(root)
        json_write_response(root, file);

    return Status_OK;
}

// Add setting to the JSON response array
static bool add_bitmap_setting (cJSON *settings, const setting_detail_t *setting)
{
    bool ok;
    cJSON *settingobj;

    if((ok = setting && (setting->is_available == NULL || setting->is_available(setting)))) {

        char opt[50], labeltxt[50], name[30], *label;
        const setting_group_detail_t *group = setting_get_group_details(setting->group);

        uint32_t i, j = strnumentries(setting->format, ',');
        for(i = 0; i < j; i++) {

            if(strcmp((label = strgetentry(opt, setting->format, i, ',')), "N/A")) {

                strcpy(labeltxt, label);
                if((label = strchr(strcpy(name, setting->name), '/')))
                    *label = '\\';

                ok = !!(settingobj = cJSON_CreateObject());

                ok  = !!cJSON_AddStringToObject(settingobj, "F", strcat(strcat(strcpy(opt, name), "/"), group->name));
                ok &= !!cJSON_AddStringToObject(settingobj, "P", strcat(strcat(strcpy(opt, uitoa(setting->id)), "#"), uitoa(i)));
                ok &= !!cJSON_AddStringToObject(settingobj, "T", "B");
                ok &= !!cJSON_AddStringToObject(settingobj, "V", get_int_setting_value(setting, 0) & (1 << i) ? "1" : "0");
                ok &= !!cJSON_AddStringToObject(settingobj, "H", labeltxt);
                if(setting->reboot_required)
                    ok &= !!cJSON_AddStringToObject(settingobj, "R", "1");

                cJSON *option, *options = cJSON_AddArrayToObject(settingobj, "O");

                option = cJSON_CreateObject();
                cJSON_AddStringToObject(option, "On", "1");
                cJSON_AddItemToArray(options, option);
                option = cJSON_CreateObject();
                cJSON_AddStringToObject(option, "Off", "0");
                cJSON_AddItemToArray(options, option);

                if(ok)
                    cJSON_AddItemToArray(settings, settingobj);
            }
        }
    }

    return ok;
}


// Add setting to the JSON response array
static bool add_axismask_setting (cJSON *settings, const setting_detail_t *setting)
{
    bool ok;
    cJSON *settingobj;

    if((ok = setting && (setting->is_available == NULL || setting->is_available(setting)))) {

        char opt[50];
        const setting_group_detail_t *group = setting_get_group_details(setting->group);

        uint32_t i;
        for(i = 0; i < N_AXIS; i++) {

            ok = !!(settingobj = cJSON_CreateObject());

            ok  = !!cJSON_AddStringToObject(settingobj, "F", strcat(strcat(strcpy(opt, setting->name), "/"), group->name));
            ok &= !!cJSON_AddStringToObject(settingobj, "P", strcat(strcat(strcpy(opt, uitoa(setting->id)), "#"), uitoa(i)));
            ok &= !!cJSON_AddStringToObject(settingobj, "T", "B");
            ok &= !!cJSON_AddStringToObject(settingobj, "V", get_int_setting_value(setting, 0) & (1 << i) ? "1" : "0");
            ok &= !!cJSON_AddStringToObject(settingobj, "H", axis_letter[i]);
            if(setting->reboot_required)
                ok &= !!cJSON_AddStringToObject(settingobj, "R", "1");

            cJSON *option, *options = cJSON_AddArrayToObject(settingobj, "O");

            option = cJSON_CreateObject();
            cJSON_AddStringToObject(option, "On", "1");
            cJSON_AddItemToArray(options, option);
            option = cJSON_CreateObject();
            cJSON_AddStringToObject(option, "Off", "0");
            cJSON_AddItemToArray(options, option);

            if(ok)
                cJSON_AddItemToArray(settings, settingobj);
        }
    }

    return ok;
}

// Add setting to the JSON response array
static bool add_setting (cJSON *settings, const setting_detail_t *setting, int32_t bit, uint_fast16_t offset)
{
    static const char *tmap[] = { "B", "M", "X", "B", "M", "I", "F", "S", "S", "A", "I", "I" };

    bool ok;
    cJSON *settingobj;

    if(setting->datatype == Format_Bitfield)
        return add_bitmap_setting(settings, setting);

    if(setting->datatype == Format_AxisMask)
        return add_axismask_setting(settings, setting);

    if((ok = setting && (setting->is_available == NULL || setting->is_available(setting)) && !!(settingobj = cJSON_CreateObject()))) {

        char opt[50];
        uint32_t name_ofs = *setting->name == '?' ? 2 : 0;
        const setting_group_detail_t *group = setting_get_group_details(setting->group + offset);

        if(setting->datatype == Format_Bool)
            bit = 0;

        strcpy(opt, group->name);
        strcat(opt, "/");
        strcat(opt, group->name);

        ok  = !!cJSON_AddStringToObject(settingobj, "F", opt);

        strcpy(opt, uitoa(setting->id));
        if(bit >= 0) {
            strcat(opt, "#");
            strcat(opt, uitoa(bit));
        }
        ok &= !!cJSON_AddStringToObject(settingobj, "P", opt);
        ok &= !!cJSON_AddStringToObject(settingobj, "T", tmap[setting->datatype]);
        ok &= !!cJSON_AddStringToObject(settingobj, "V", bit == -1 ? setting_get_value(setting, offset) : get_int_setting_value(setting, offset) & (1 << bit) ? "1" : "0");
        ok &= !!cJSON_AddStringToObject(settingobj, "H", bit == -1 || setting->datatype == Format_Bool ? setting->name + name_ofs : strgetentry(opt, setting->format, bit, ','));
        if(setting->reboot_required)
            ok &= !!cJSON_AddStringToObject(settingobj, "R", "1");

        if(ok) switch(setting->datatype) {

            case Format_Bool:
            case Format_Bitfield:
            case Format_XBitfield:
            case Format_RadioButtons:
                {
                    cJSON *option, *options = cJSON_AddArrayToObject(settingobj, "O");
                    if(bit == -1) {
                        uint32_t i, j = strnumentries(setting->format, ',');
                        for(i = 0; i < j; i++) {
                            option = cJSON_CreateObject();
                      //      if(isv3 && i == 0)
                      //          cJSON_AddStringToObject(option, strgetentry(opt, setting->format, i, ','), uitoa(1 << bit));
                      //      else
                            if(strcmp(strgetentry(opt, setting->format, i, ','), "N/A")) {
                                cJSON_AddStringToObject(option, opt, uitoa(i));
                                cJSON_AddItemToArray(options, option);
                            }
                        }
                    } else {
                        option = cJSON_CreateObject();
                        cJSON_AddStringToObject(option, "Enabled", "1");
                        cJSON_AddItemToArray(options, option);
                        option = cJSON_CreateObject();
                        cJSON_AddStringToObject(option, "Disabled", "0");
                        cJSON_AddItemToArray(options, option);
                    }
                }
                break;

            case Format_IPv4:
                break;

            default:
                if(setting->min_value && !setting_is_list(setting))
                    ok &= !!cJSON_AddStringToObject(settingobj, "M", setting->min_value);
                if(setting->max_value)
                    ok &= !!cJSON_AddStringToObject(settingobj, "S", setting->max_value);
                break;

        }

        if(ok)
            cJSON_AddItemToArray(settings, settingobj);
    }

    return ok;
}
/*
// ESP400
static status_code_t get_settings (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    bool ok;
    cJSON *root = cJSON_CreateObject(), *settings = NULL;

    if((ok = root != NULL)) {
        ok &= !!cJSON_AddStringToObject(root, "cmd", uitoa(command->id));
        ok &= !!cJSON_AddStringToObject(root, "status", "ok");
    }

    if((ok &= !!(settings = cJSON_AddArrayToObject(root, "data")))) {

        add_setting(settings, Setting_Hostname, -1, 0);
#if HTTP_ENABLE
        add_setting(settings, Setting_NetworkServices, 2, 0);
        add_setting(settings, Setting_HttpPort, -1, 0);
#endif
#if TELNET_ENABLE
        add_setting(settings, Setting_NetworkServices, 0, 0);
        add_setting(settings, Setting_TelnetPort, -1, 0);
#endif
#if WEBSOCKET_ENABLE
        add_setting(settings, Setting_NetworkServices, 1, 0);
        add_setting(settings, Setting_WebSocketPort, -1, 0);
#endif
#if FTP_ENABLE
        add_setting(settings, Setting_NetworkServices, 3, 0);
        add_setting(settings, Setting_FtpPort, -1, 0);
#endif
        add_setting(settings, Setting_IpMode, -1, 0);
//        add_setting(settings, Setting_ReportInches, -1, 0);
#if ETHERNET_ENABLE
        add_setting(settings, Setting_IpAddress, -1, 0);
        add_setting(settings, Setting_Gateway, -1, 0);
        add_setting(settings, Setting_NetMask, -1, 0);
#endif
#if WIFI_ENABLE
        add_setting(settings, Setting_WifiMode, -1, 0);

        add_setting(settings, Setting_WiFi_STA_SSID, -1, 0);
        add_setting(settings, Setting_WiFi_STA_Password, -1, 0);
        add_setting(settings, Setting_IpMode, -1, 0);
        add_setting(settings, Setting_IpAddress, -1, 0);
        add_setting(settings, Setting_Gateway, -1, 0);
        add_setting(settings, Setting_NetMask, -1, 0);

        add_setting(settings, Setting_WiFi_AP_SSID, -1, 0);
        add_setting(settings, Setting_WiFi_AP_Password, -1, 0);
        add_setting(settings, Setting_IpAddress2, -1, 0);

#endif
#if BLUETOOTH_ENABLE
//      add_setting(settings, Setting_WifiMode, -1, 0);
#endif

        json_write_response(root, file);
        root = NULL;
    }

    if(root)
        cJSON_Delete(root);

    return Status_OK;
}
*/
static bool add_setting2 (const setting_detail_t *setting, uint_fast16_t offset, void *settings)
{
    return add_setting((cJSON *)settings, setting, -1, offset);
}

// ESP400
static status_code_t get_settings (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    bool ok;
    uint_fast16_t idx;
    cJSON *root = cJSON_CreateObject(), *settings = NULL;
    setting_details_t *details = settings_get_details();
    const setting_detail_t *setting;

    if((ok = root != NULL)) {
        ok &= !!cJSON_AddStringToObject(root, "cmd", uitoa(command->id));
        ok &= !!cJSON_AddStringToObject(root, "status", "ok");
    }

    if((ok &= !!(settings = cJSON_AddArrayToObject(root, "data")))) do {
        for(idx = 0; idx < details->n_settings; idx++) {
            setting = &details->settings[idx];
            if(setting->is_available == NULL || setting->is_available(setting))
                settings_iterator(setting, add_setting2, settings);
        }
    } while((details = details->next));

    if(root)
        json_write_response(root, file);

    return Status_OK;
}

// ESP401
static status_code_t set_setting (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    bool ok = false;
    char *setting_id = webui_get_arg(argc, argv, "P=");
    char *value = webui_get_arg(argc, argv, "V=");
    status_code_t status = Status_Unhandled;

    if(setting_id && value) {

        char *bitp;
        const setting_detail_t *setting;

        // "hack" for bitfield settings
        if((bitp = strchr(setting_id, '#'))) {

            *bitp++ = '\0';
            uint32_t pmask = 1 << atoi(bitp), tmask;

            if((ok = !!(setting = setting_get_details(atoi(setting_id), NULL)))) {

                tmask = get_int_setting_value(setting, 0);

                if(*value == '0')
                    tmask ^= pmask;
                else
                    tmask |= pmask;

                if(setting->datatype == Format_XBitfield && (tmask & 0x01) == 0)
                    tmask = 0;

                value = uitoa(tmask);
            }
        } else
            ok = !!(setting = setting_get_details((setting_id_t)atoi(setting_id), NULL));

        if(ok)
            status = sys_set_setting(setting->id, value);
    }

    if(json) {

        cJSON *root;

        if((ok = !!(root = json_create_response_hdr(command->id, false, status == Status_OK, NULL, status == Status_OK ? "ok" : "Set failed"))))
            json_write_response(root, file);

    } else
        report_status_message(status);

    return status;
}

// Add value to the JSON response array
static bool add_system_value (cJSON *settings, char *id, char *value)
{
    bool ok = true;

    cJSON *setting;

    if((ok = !!(setting = cJSON_CreateObject())))
    {
        ok  = !!cJSON_AddStringToObject(setting, "id", id);
        ok &= !!cJSON_AddStringToObject(setting, "value", value);

        if(ok)
            cJSON_AddItemToArray(settings, setting);
    }

    return ok;
}

// ESP420
status_code_t webui_v3_get_system_status (uint_fast16_t command_id, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    char buf[200];
    vfs_free_t *mount;
    vfs_drive_t *sdfs = fs_get_sd_drive(); //, *flashfs = fs_get_flash_drive();
    network_info_t *network = networking_get_info();

    mount = sdfs ? vfs_drive_getfree(sdfs) : NULL;

    if(json) {

        bool ok;
        cJSON *root, *data;

        if((ok = !!(root = json_create_response_hdr(command_id, true, true, &data, NULL)))) {

//            ok &= add_system_value(data, "chip id", "0");
            ok &= add_system_value(data, "CPU Freq", strcat(strcpy(buf, uitoa(hal.f_mcu ? hal.f_mcu : hal.f_step_timer / 1000000UL)), " MHz"));

            if(mount) {

                ok &= add_system_value(data, "FS type", "SD");

                strcpy(buf, btoa(mount->size)); // assuming 512 byte sector size
                strcat(buf, "/");
                strcat(buf, btoa(mount->used));
                ok &= add_system_value(data, "FS usage", buf);
            }

#if WIFI_ENABLE
            ok &= add_system_value(data, "wifi", "ON");
#elif ETHERNET_ENABLE
            ok &= add_system_value(data, "wifi", "OFF");
            ok &= add_system_value(data, "ethernet", "ON");
#endif
            if(network->status.services.http)
                ok &= add_system_value(data, "HTTP port", uitoa(network->status.http_port));
            if(network->status.services.telnet)
                ok &= add_system_value(data, "Telnet port", uitoa(network->status.telnet_port));
            if(network->status.services.webdav)
                ok &= add_system_value(data, "WebDav port", uitoa(network->status.http_port));
            if(network->status.services.ftp) {
                strappend(buf, 3, uitoa(network->status.ftp_port), "/", uitoa(network->status.ftp_port));
                ok &= add_system_value(data, "Ftp ports", buf);
            }
            if(network->status.services.websocket)
                ok &= add_system_value(data, "Websocket port", uitoa(network->status.websocket_port));

            if(network->is_ethernet) {

                if(*network->mac != '\0')
                    ok &= add_system_value(data, "ethernet", network->mac);

                if(network->link_up)
                    strappend(buf, 3, "connected (", uitoa(network->mbps), "Mbps)");
                else
                    strcpy(buf, "disconnected");
                ok &= add_system_value(data, "cable", buf);

                ok &= add_system_value(data, "ip mode", network->status.ip_mode == IpMode_Static ? "static" : "dhcp");
                ok &= add_system_value(data, "ip", network->status.ip);

                if(*network->status.gateway != '\0')
                    ok &= add_system_value(data, "gw", network->status.gateway);

                if(*network->status.mask != '\0')
                    ok &= add_system_value(data, "msk", network->status.mask);

                if(network->status.services.dns)
                    ok &= add_system_value(data, "DNS", network->status.gateway);
            }

#if WEBUI_AUTH_ENABLE
            ok &= add_system_value(data, "authentication", "ON");
#endif
//            ok &= add_system_value(data, "flash", "OFF");
            if(sdfs)
                strappend(buf, 3, "direct (", sdfs->name, ")");
            else
                strcpy(buf, "none");
            ok &= add_system_value(data, "sd", buf);

            ok &= add_system_value(data, "targetfw", FIRMWARE_TARGET);
            strappend(buf, 3, GRBL_VERSION, "-", uitoa(GRBL_BUILD));
            ok &= add_system_value(data, "FW ver", buf);
            ok &= add_system_value(data, "FW arch", hal.info);

            json_write_response(root, file);
        }
    } else {

//        vfs_puts(strappend(buf, 3, "chip id: ", "0", WEBUI_EOL), file);
        vfs_puts(strappend(buf, 3, "CPU Freq: ", uitoa(hal.f_mcu ? hal.f_mcu : hal.f_step_timer / 1000000UL), "MHz" WEBUI_EOL), file);

        if(sdfs) {

            vfs_puts("FS type: SD" WEBUI_EOL, file);

            strcpy(buf, "FS usage: ");
            strcat(buf, btoa(mount->size)); // assuming 512 byte sector size
            strcat(buf, "/");
            strcat(buf, btoa(mount->used));
            strcat(buf, WEBUI_EOL);
            vfs_puts(buf, file);
        }

#if WIFI_ENABLE
        vfs_puts("wifi: ON" WEBUI_EOL, file);
#elif ETHERNET_ENABLE
        vfs_puts("wifi: OFF" WEBUI_EOL, file);
        vfs_puts("ethernet: ON" WEBUI_EOL, file);
#endif
        if(network->status.services.http)
            vfs_puts(strappend(buf, 3, "HTTP port: ", uitoa(network->status.http_port), WEBUI_EOL), file);
        if(network->status.services.telnet)
            vfs_puts(strappend(buf, 3, "Telnet port: ", uitoa(network->status.telnet_port), WEBUI_EOL), file);
        if(network->status.services.ftp)
            vfs_puts(strappend(buf, 5, "Ftp ports: ", uitoa(network->status.ftp_port), "/", uitoa(network->status.ftp_port), WEBUI_EOL), file);
        if(network->status.services.websocket)
            vfs_puts(strappend(buf, 3, "Websocket port: ", uitoa(network->status.websocket_port), WEBUI_EOL), file);

        if(network->is_ethernet) {

            if(*network->mac != '\0')
                vfs_puts(strappend(buf, 3, "ethernet: ", network->mac, WEBUI_EOL), file);
            vfs_puts(network->link_up
                              ? strappend(buf, 4, "cable: connected (", uitoa(network->mbps), "Mbps)", WEBUI_EOL)
                              : strappend(buf, 2, "cable: disconnected", WEBUI_EOL), file);

            vfs_puts(strappend(buf, 3, "ip mode: ", network->status.ip_mode == IpMode_Static ? "static" : "dhcp", WEBUI_EOL), file);
            vfs_puts(strappend(buf, 3, "ip: ", network->status.ip, WEBUI_EOL), file);

            if(*network->status.gateway != '\0')
                vfs_puts(strappend(buf, 3, "gw: ", network->status.gateway, WEBUI_EOL), file);

            if(*network->status.mask != '\0')
                vfs_puts(strappend(buf, 3, "msk: ", network->status.mask, WEBUI_EOL), file);

            if(network->status.services.dns)
                vfs_puts(strappend(buf, 3, "DNS: ", network->status.gateway, WEBUI_EOL), file);
        }

#if WEBUI_AUTH_ENABLE
        vfs_puts("authentication: ON" WEBUI_EOL, file);
#endif
//          vfs_puts("flash: OFF" WEBUI_EOL);
        if(sdfs)
            vfs_puts(strappend(buf, 4, "sd direct (", sdfs->name, ")" WEBUI_EOL), file);
        else
            vfs_puts("sd: none" WEBUI_EOL, file);
        vfs_puts("targetfw: " FIRMWARE_TARGET WEBUI_EOL, file);
        vfs_puts(strappend(buf, 5, "FW ver: ", GRBL_VERSION, "-", uitoa(GRBL_BUILD), WEBUI_EOL), file);
        vfs_puts(strappend(buf, 3, "FW arch: ", hal.info, WEBUI_EOL), file);
    }

    return Status_OK;
}

static status_code_t get_system_status (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    return webui_v3_get_system_status(command->id, argc, argv, json, file);
}

// ESP701
static status_code_t handle_job_status (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    bool ok;
    sdcard_job_t *job = sdcard_get_job_info();
    cJSON *root, *data;
    char *action = webui_get_arg(argc, argv, "action=");

    if((ok = !!(root = json_create_response_hdr(command->id, false, true, &data, NULL)))) {

        if(action) {

            switch(strlookup(action, "pause,resume,abort", ',')) {

                case 0:
                    if(job)
                        grbl.enqueue_realtime_command(CMD_FEED_HOLD);
                    ok &= !!cJSON_AddStringToObject(data, "status", job ? "Stream paused" : "No stream to pause");
                    break;

                case 1:
                    if(job)
                        grbl.enqueue_realtime_command(CMD_CYCLE_START);
                    ok &= !!cJSON_AddStringToObject(data, "status", job ? "Stream resumed" : "No stream to resume");
                    break;

                case 2:
                    if(job)
                        grbl.enqueue_realtime_command(CMD_STOP);
                    ok &= !!cJSON_AddStringToObject(data, "status", job ? "Stream aborted" : "No stream to abort");
                    break;

                default:
                    ok &= !!cJSON_AddStringToObject(data, "status", "Unknown action");
                    break;
            }

        } else if(job) {

            switch(state_get()) {

                case STATE_HOLD:
                    ok &= !!cJSON_AddStringToObject(data, "status", "pause stream");
                    break;

                default:
                    ok &= !!cJSON_AddStringToObject(data, "status", "processing");
                    ok &= !!cJSON_AddStringToObject(data, "total", uitoa(job->size));
                    ok &= !!cJSON_AddStringToObject(data, "processed", uitoa(job->pos));
                    ok &= !!cJSON_AddStringToObject(data, "type", "SD");
                    ok &= !!cJSON_AddStringToObject(data, "name", job->name);
                    break;
            }

        } else {

            ok &= !!cJSON_AddStringToObject(data, "status", "no stream");
            if(gc_state.last_error != Status_OK)
                ok &= !!cJSON_AddStringToObject(data, "code", uitoa(gc_state.last_error));
        }
    }

    if(root)
        json_write_response(root, file);

    return Status_OK;
}

// ESP800
static status_code_t get_firmware_spec (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    char buf[200], hostpath[16];
    network_info_t *network = networking_get_info();
    vfs_drive_t *sdfs = fs_get_sd_drive(), *flashfs = fs_get_flash_drive();

//    strcpy(hostpath, webui_get_sys_path());
//    if(*hostpath == '\0')
        strcpy(hostpath, sdfs && flashfs == NULL ? "/www" : "/");
//    vfs_fixpath(hostpath);

    if(json) {

        bool ok;
        cJSON *root, *data;

        if((ok = !!(root = json_create_response_hdr(command->id, false, true, &data, NULL)))) {

            ok &= !!cJSON_AddStringToObject(data, "FWVersion", GRBL_VERSION);
            ok &= !!cJSON_AddStringToObject(data, "FWTarget", FIRMWARE_TARGET);
            ok &= !!cJSON_AddStringToObject(data, "FWTargetID", FIRMWARE_ID);
            ok &= !!cJSON_AddStringToObject(data, "Setup", "Enabled");
            ok &= !!cJSON_AddStringToObject(data, "SDConnection", sdfs ? "direct" : "none");
            ok &= !!cJSON_AddStringToObject(data, "SerialProtocol", "Socket");
#if WEBUI_AUTH_ENABLE
            ok &= !!cJSON_AddStringToObject(data, "Authentication", "Enabled");
#else
            ok &= !!cJSON_AddStringToObject(data, "Authentication", "Disabled");
#endif
            ok &= !!cJSON_AddStringToObject(data, "WebCommunication", "Synchronous");
            ok &= !!cJSON_AddStringToObject(data, "WebSocketIP", network->status.ip);
            ok &= !!cJSON_AddStringToObject(data, "WebSocketSubProtocol", "webui-v3");
            ok &= !!cJSON_AddStringToObject(data, "WebSocketPort", uitoa(network->status.websocket_port));
            ok &= !!cJSON_AddStringToObject(data, "Hostname", network->status.hostname);
#if WIFI_ENABLE
  #if WIFI_SOFTAP
            ok &= !!cJSON_AddStringToObject(data, "WiFiMode", "AP");
  #else
            ok &= !!cJSON_AddStringToObject(data, "WiFiMode", "STA");
  #endif
#endif
            ok &= !!cJSON_AddStringToObject(data, "FlashFileSystem", flashfs ? flashfs->name : "none");
            ok &= !!cJSON_AddStringToObject(data, "HostPath", hostpath);
            ok &= !!cJSON_AddStringToObject(data, "WebUpdate", /*flashfs || sdfs ? "Enabled" :*/ "Disabled");
            ok &= !!cJSON_AddStringToObject(data, "FileSystem", flashfs ? "flash" : "none");
            if(hal.rtc.get_datetime) {
                struct tm time;
                ok &= !!cJSON_AddStringToObject(data, "Time", hal.rtc.get_datetime(&time) ? "Manual" : "Not set");
            } else
                ok &= !!cJSON_AddStringToObject(data, "Time", "none");

            json_write_response(root, file);
        }
    } else {

        vfs_puts("FW version:" GRBL_VERSION WEBUI_EOL, file);
        vfs_puts("FW target:" FIRMWARE_TARGET WEBUI_EOL, file);
        vfs_puts("FW ID:" FIRMWARE_ID WEBUI_EOL, file);
        vfs_puts(strappend(buf, 3, "SD connection:", sdfs ? "direct" : "none", WEBUI_EOL), file);
        vfs_puts("Serial protocol:Socket" WEBUI_EOL, file);
#if WEBUI_AUTH_ENABLE
        vfs_puts("Authentication:Enabled" WEBUI_EOL, file);
#else
        vfs_puts("Authentication:Disabled" WEBUI_EOL, file);
#endif
        vfs_puts("Web Communication:Synchronous" WEBUI_EOL, file);
        vfs_puts(strappend(buf, 3, "Web Socket IP:", network->status.ip, WEBUI_EOL), file);
        vfs_puts(strappend(buf, 3, "Web Socket Port:", uitoa(network->status.websocket_port), WEBUI_EOL), file);
        vfs_puts(strappend(buf, 3, "Hostname:", network->status.hostname, WEBUI_EOL), file);
#if WIFI_ENABLE
#if WIFI_SOFTAP
        vfs_puts("WiFi mode:AP" WEBUI_EOL, file);
#else
        vfs_puts("WiFi mode:STA" WEBUI_EOL, file);
#endif
#endif
        vfs_puts("WebUpdate:Enabled" WEBUI_EOL, file);
        if(flashfs)
            vfs_puts(strappend(buf, 3, "FlashFileSystem:", flashfs->name, WEBUI_EOL), file);

        vfs_puts(strappend(buf, 3, "HostPath:", hostpath, WEBUI_EOL), file);

        if(hal.rtc.get_datetime) {
            struct tm time;
            if(hal.rtc.get_datetime(&time))
                vfs_puts("Time:Manual" WEBUI_EOL, file);
            else
                vfs_puts("Time:Not set" WEBUI_EOL, file);
        } else
            vfs_puts("Time:none" WEBUI_EOL, file);
    }

    return Status_OK;
}

// ESP111
static status_code_t get_current_ip (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    char response[20];

    if(json)
        json_write_response(json_create_response_hdr(command->id, false, true, NULL, networking_get_info()->status.ip), file);
    else
        vfs_puts(strappend(response, 3, argv[0], networking_get_info()->status.ip, WEBUI_EOL), file);

    return Status_OK;
}

// ESP140
static status_code_t get_set_time (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    bool ok = false;
    char buf[50];

    if(hal.rtc.get_datetime) {
 
       if(argc) {

            bool sync = !!webui_get_arg(argc, argv, "SYNC"),
                 now = !!webui_get_arg(argc, argv, "NOW"),
                 dst = webui_get_bool_arg(argc, argv, "dst=");
            char *srv1 = webui_get_arg(argc, argv, "srv1="),
                 *srv2 = webui_get_arg(argc, argv, "srv2="),
                 *srv3 = webui_get_arg(argc, argv, "srv3="),
                 *time = webui_get_arg(argc, argv, "time="),
                 *dstp = webui_get_arg(argc, argv, "dst="),
                 *zone = webui_get_arg(argc, argv, "zone=");

            webui_trim_arg(&argc, argv, "SYNC");
            webui_trim_arg(&argc, argv, "NOW");
            webui_trim_arg(&argc, argv, "dst=");
            webui_trim_arg(&argc, argv, "srv1=");
            webui_trim_arg(&argc, argv, "srv2=");
            webui_trim_arg(&argc, argv, "srv3=");
            webui_trim_arg(&argc, argv, "time=");
            webui_trim_arg(&argc, argv, "zone=");

            UNUSED(sync);
            UNUSED(now);
            UNUSED(dst);
            UNUSED(srv1);
            UNUSED(srv2);
            UNUSED(srv3);
            UNUSED(zone);

            ok = argc == 0;

            if(srv1 && ok) {
                ok = false;
                strcpy(buf, "Set server 1 failed");
            }

            if(srv2 && ok) {
                ok = false;
                strcpy(buf, "Set server 2 failed");
            }

            if(srv3 && ok) {
                ok = false;
                strcpy(buf, "Set server 3 failed");
            }

            if(zone && ok) {
                ok = false;
                strcpy(buf, "Set time zone failed");
            }

            if(dstp && ok) {
                ok = false;
                strcpy(buf, "Set daylight failed");
            }

            if(time && ok) {
                struct tm *dt;
                if(strlen(time) > 16) {
                    time[10] = 'T';
                    time[13] = ':';
                    time[16] = ':';
                }
                if(!(ok = hal.rtc.set_datetime && (dt = get_datetime(time)) && hal.rtc.set_datetime(dt)))
                    strcpy(buf, "Set time failed");
            }

            if(sync && ok) {
                ok = false;
                strcpy(buf, "Time is manual");
            }

            if(now && ok) {
                struct tm time;
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-overflow"
#endif
                if((hal.rtc.get_datetime(&time)))
                    sprintf(buf, "%4d-%02d-%02dT%02d:%02d:%02d", time.tm_year + 1900, time.tm_mon + 1, time.tm_mday, time.tm_hour, time.tm_min, time.tm_sec);
                else
                    strcpy(buf, "Time not available");
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
            }

            if(!ok || *buf == '\0' || argc) {
                ok = false;
                strcpy(buf, "No parameter");
            }

            if(json)
                json_write_response(json_create_response_hdr(command->id, false, ok, NULL, buf), file);
            else {
                vfs_puts(buf, file);
                vfs_puts(WEBUI_EOL, file);
            }

        } else {

            if(json) {

                cJSON *root, *data;

                if((ok = !!(root = json_create_response_hdr(command->id, false, true, &data, NULL)))) {

                    ok &= !!cJSON_AddStringToObject(data, "srv1", "");
                    ok &= !!cJSON_AddStringToObject(data, "srv2", "");
                    ok &= !!cJSON_AddStringToObject(data, "srv3", "");
                    ok &= !!cJSON_AddStringToObject(data, "zone", "GMT");
                    ok &= !!cJSON_AddStringToObject(data, "dst", "NO");

                    json_write_response(root, file);
                }
            } else {
                vfs_puts(strappend(buf, 3, "srv1=", "", WEBUI_EOL), file);
                vfs_puts(strappend(buf, 3, "srv2=", "", WEBUI_EOL), file);
                vfs_puts(strappend(buf, 3, "srv3=", "", WEBUI_EOL), file);
                vfs_puts(strappend(buf, 3, "zone=", "GMT", WEBUI_EOL), file);
                vfs_puts(strappend(buf, 3, "dst=", "NO", WEBUI_EOL), file);
            }
        }
    } else {
        if(json)
            json_write_response(json_create_response_hdr(command->id, false, false, NULL, "N/A"), file);
        else
            vfs_puts("N/A" ASCII_EOL, file);
    }

    return Status_OK;
}

// ESP200
static status_code_t get_sd_status (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    char *msg;

    if(argc == 1) {

        bool refresh = !!webui_get_arg(argc, argv, "REFRESH"), release = !!webui_get_arg(argc, argv, "RELEASE");

        UNUSED(refresh);

        webui_trim_arg(&argc, argv, "REFRESH"); // Mount?
        webui_trim_arg(&argc, argv, "RELEASE"); // Unmount?

        msg = argc ? "Unknown parameter" : (release ? "SD card released" : "SD card ok");

    } else
        msg = hal.stream.type == StreamType_SDCard ? "Busy" : (sdcard_getfs() ? "SD card detected" : "Not available");

    if(json)
        json_write_response(json_create_response_hdr(command->id, false, true, NULL, msg), file);
    else {
        vfs_puts(msg, file);
        vfs_puts(WEBUI_EOL, file);
    }

    return Status_OK;
}

// ESP220
static const char *get_pinname (pin_function_t function)
{
    const char *name = NULL;
    uint_fast8_t idx = sizeof(pin_names) / sizeof(pin_name_t);

    do {
        if(pin_names[--idx].function == function)
            name = pin_names[idx].name;
    } while(idx && !name);

    return name ? name : "N/A";
}

static void show_pin_json (xbar_t *pin, void *data)
{
    char id[10];

    strcat(strcpy(id, (char *)pin->port), uitoa(pin->pin));

    add_system_value((cJSON *)data, (char *)get_pinname(pin->function), id);
}

static void show_pin_txt (xbar_t *pin, void *file)
{
    char buf[50];

    vfs_puts(strappend(buf, 5, (char *)pin->port, uitoa(pin->pin), ": ", get_pinname(pin->function), WEBUI_EOL), (vfs_file_t *)file);
}

static status_code_t show_pins (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    if(json) {

        cJSON *root, *data;

        if(hal.enumerate_pins && !!(root = json_create_response_hdr(command->id, true, true, &data, NULL))) {
            hal.enumerate_pins(false, show_pin_json, data);
            json_write_response(root, file);
        }
    } else
        hal.enumerate_pins(false, show_pin_txt, file);

    return Status_OK; // for now
}

#if WIFI_ENABLE

// ESP410
static status_code_t get_ap_list (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    bool ok = false;

    ap_list_t *ap_list = wifi_get_aplist();

    if(ap_list && ap_list->ap_records) {

        cJSON *root;

        if((root = cJSON_CreateObject())) {

            cJSON *ap, *aps;

            if((aps = cJSON_AddArrayToObject(root, "AP_LIST"))) {

                for(int i = 0; i < ap_list->ap_num; i++) {
                    if((ok = !!(ap = cJSON_CreateObject())))
                    {
                        ok = !!cJSON_AddStringToObject(ap, "SSID", (char *)ap_list->ap_records[i].ssid);
                        ok &= !!cJSON_AddNumberToObject(ap, "SIGNAL", (double)ap_list->ap_records[i].rssi);
                        ok &= !!cJSON_AddStringToObject(ap, "IS_PROTECTED", ap_list->ap_records[i].authmode == WIFI_AUTH_OPEN ? "0" : "1");
                        if(ok)
                            cJSON_AddItemToArray(aps, ap);
                    }
                }
            }

            if(ok)
                json_write_response(root, file);
            else
                cJSON_Delete(root);
        }
    }

    if(ap_list)
        wifi_release_aplist();

    return Status_OK; // for now
}

#endif

static inline char *get_path (char *buf, char *path, vfs_drive_t *drive)
{
    *buf = '\0';

    if(strlen(drive->path) > 1 || *drive->path != '/')
        strcpy(buf, drive->path);

    return strcat(buf, path);
}

static status_code_t fs_list_files (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file, vfs_drive_t *drive)
{
    bool ok;
    char path[255];
    cJSON *root = NULL;

    if(drive) {

        char *arg = webui_get_arg(argc, argv, NULL);

        if(json) {

            cJSON *data;

            if((ok = !!(root = json_create_response_hdr(command->id, false, true, &data, NULL)))) {
                ok &= !!cJSON_AddStringToObject(data, "path", get_path(path, arg ? arg : "/", drive));
                ok &= fs_ls(data, path, NULL, drive);
            }
        }
    } else
        json_write_response(json_create_response_hdr(command->id, false, false, NULL, "Not mounted"), file);

    if(root)
        json_write_response(root, file);

    return Status_OK; // for now
}

static status_code_t fs_action (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file, vfs_drive_t *drive)
{
    bool ok = false;
    char response[24] = "";
    char path[256];

    if(drive == NULL)
        strcpy(path, "Not available");

    else if(argc == 1) {

         char *create = webui_get_arg(argc, argv, "create="),
              *exists = webui_get_arg(argc, argv, "exists="),
              *remove = webui_get_arg(argc, argv, "remove="),
              *mkdir = webui_get_arg(argc, argv, "mkdir="),
              *rmdir = webui_get_arg(argc, argv, "rmdir=");

         if(create) {

             vfs_file_t *file;
             if((ok = (file = vfs_open(get_path(path, create, drive), "wb"))))
                 vfs_close(file);
             else
                 strcpy(response, "create failed");

         } else if(exists) {

             vfs_stat_t st;
             ok = true;
             strcpy(response, vfs_stat(get_path(path, exists, drive), &st) == 0 ? "yes" : "no");

         } else if(remove) {

             if(!(ok = vfs_unlink(get_path(path, remove, drive)) == 0))
                 strcpy(response, "remove failed");

         } else if(mkdir) {

             if(!(ok = vfs_mkdir(get_path(path, mkdir, drive)) == 0))
                 strcpy(response, "mkdir failed");

         } else if(rmdir) {

             if(!(ok = vfs_rmdir(get_path(path, rmdir, drive)) == 0))
                 strcpy(response, "rmdir failed");

         } else
             strcpy(response, "Missing parameter");
    } else
        strcpy(response, argc ? "Unknown parameter" : "Missing parameter");

    if(*response == '\0')
        strcpy(response, "ok");

    if(json)
        json_write_response(json_create_response_hdr(command->id, false, ok, NULL, response), file);
    else
        vfs_puts(response, file);

    return Status_OK; // for now
}

// ESP700
static status_code_t flash_read_file (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    bool ok = false;
    char *cmd = webui_get_arg(argc, argv, NULL), msg[50];
    vfs_drive_t *drive = fs_get_flash_drive();

    if(cmd == NULL || strlen(cmd) == 0)
        strcpy(msg, "Missing parameter");
    else if(hal.stream.type == StreamType_File)
        strcpy(msg, "Streaming already in progress");
    else if(drive) {
        char path[256];
        get_path(path, cmd, drive);
        if(!(ok = stream_file(state_get(), path) == Status_OK))
            strcpy(msg, "Error processing file");
    } else
        strcpy(msg, "Flash filesystem not available");

    if(json)
        json_write_response(json_create_response_hdr(command->id, false, ok, NULL, msg), file);
    else
        vfs_puts(strcat(msg, WEBUI_EOL), file);

    return Status_OK;
}

// ESP710
static status_code_t flash_format (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    bool ok;
    char *cmd = webui_get_arg(argc, argv, NULL);

    vfs_drive_t *drive = fs_get_flash_drive();

    if((ok = !strcmp(cmd, "FORMATFS") && drive)) {
        if(!json)
            vfs_puts("Start Formating" WEBUI_EOL, file); // sic
        ok = vfs_drive_format(drive) == 0;
    }

    if(json)
        json_write_response(json_create_response_hdr(command->id, false, ok, NULL, ok ? "ok" : "Invalid parameter"), file);
    else
        vfs_puts(ok ? "ok" WEBUI_EOL : "Invalid parameter" WEBUI_EOL, file);

    return Status_OK;
}

// ESP715
static status_code_t sdcard_format (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    bool ok;
    char *cmd = webui_get_arg(argc, argv, NULL);

    vfs_drive_t *drive = fs_get_sd_drive();

    if((ok = !strcmp(cmd, "FORMATSD") && drive)) {
        if(!json)
            vfs_puts("Start Formating" WEBUI_EOL, file); // sic
        ok = vfs_drive_format(drive) == 0;
    }

    if(json)
        json_write_response(json_create_response_hdr(command->id, false, ok, NULL, ok ? "ok" : "Invalid parameter"), file);
    else
        vfs_puts(ok ? "ok" WEBUI_EOL : "Invalid parameter" WEBUI_EOL, file);

    return Status_OK;
}

// ESP720
static status_code_t flashfs_ls (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    return fs_list_files(command, argc, argv, json, file, fs_get_flash_drive());
}

// ESP730
static status_code_t flashfs_action (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    return fs_action(command, argc, argv, json, file, fs_get_flash_drive());
}

// ESP740
static status_code_t sdcard_ls (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    return fs_list_files(command, argc, argv, json, file, fs_get_sd_drive());
}

// ESP750
static status_code_t sdcard_action (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    return fs_action(command, argc, argv, json, file, fs_get_sd_drive());
}

// ESP780
static status_code_t global_fs_ls (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    return fs_list_files(command, argc, argv, json, file, fs_get_root_drive());
}

// ESP790
static status_code_t global_fs_action (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    return fs_action(command, argc, argv, json, file, fs_get_root_drive());
}

// ESP444
static status_code_t set_cpu_state (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    status_code_t status = Status_OK;

    char *cmd = webui_get_arg(argc, argv, NULL);

    if(!strcmp(cmd, "RESET")) {
        sys_state_t state = state_get();
        if (!(state == STATE_IDLE || (state & (STATE_ALARM|STATE_ESTOP)))) {
            settings_restore(settings_all);
            mc_reset(); // Force reset to ensure settings are initialized correctly.
        } else
            status = Status_IdleError;
    } else if(!strcmp(cmd, "RESTART") && hal.reboot) {
        hal.stream.write_all("[MSG:Restart ongoing]\r\n");
        hal.delay_ms(1000, hal.reboot); // do the restart after a 1s delay, to allow the response to be sent
    } else
        status = Status_InvalidStatement;

    vfs_puts(status == Status_OK ? "ok" : "Error:Incorrect Command", file);

    return status;
}

#endif // WEBUI_ENABLE
