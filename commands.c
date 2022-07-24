/*
  webui/commands.c - An embedded CNC Controller with rs274/ngc (g-code) support

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

#if WEBUI_ENABLE

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#include "../networking/networking.h"
#include "../networking/urldecode.h"
#include "../networking/utils.h"
#include "../networking/strutils.h"
#include "../networking/cJSON.h"

#include "server.h"

#include "grbl/report.h"
#include "grbl/state_machine.h"

#if SDCARD_ENABLE
#include "sdcard/sdcard.h"
//#include "esp_vfs_fat.h"
#endif

//#include "flashfs.h"

#ifndef LINE_BUFFER_SIZE
#define LINE_BUFFER_SIZE 257 // 256 characters plus terminator
#endif

#define WEBUI_EOL "\n"

static bool client_isv3 = false;

extern void data_is_json (void);

typedef enum {
    WebUIType_IPAddress = 'A',
    WebUIType_Boolean = 'B',    // v2 only
    WebUIType_Flag = 'F',       // v2 only
    WebUIType_Integer = 'I',
    WebUIType_String = 'S',
    WebUIType_Byte = 'T'        // v3
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
    status_code_t (*handler)(const struct webui_cmd_binding *command, char *args, bool json, bool isv3);
    webui_auth_required_t auth;
    const char *help;
    webui_setting_map_t setting;
} webui_cmd_binding_t;

//typedef status_code_t (*webui_command_handler_ptr)(const webui_cmd_binding_t *command, char *args, bool json, bool isv3);

static status_code_t list_commands (const struct webui_cmd_binding *command, char *args, bool json, bool isv3);
static status_code_t esp_setting (const struct webui_cmd_binding *command, char *args, bool json, bool isv3);
static status_code_t get_settings (const struct webui_cmd_binding *command, char *args, bool json, bool isv3);
static status_code_t set_setting (const struct webui_cmd_binding *command, char *args, bool json, bool isv3);
static status_code_t get_system_status (const struct webui_cmd_binding *command, char *args, bool json, bool isv3);
static status_code_t handle_job_status (const struct webui_cmd_binding *command, char *args, bool json, bool isv3);
static status_code_t get_firmware_spec (const struct webui_cmd_binding *command, char *args, bool json, bool isv3);
static status_code_t get_current_ip (const struct webui_cmd_binding *command, char *args, bool json, bool isv3);
static status_code_t get_sd_status (const struct webui_cmd_binding *command, char *args, bool json, bool isv3);
static status_code_t get_sd_content (const struct webui_cmd_binding *command, char *args, bool json, bool isv3);
static status_code_t sd_print (const struct webui_cmd_binding *command, char *args, bool json, bool isv3);
static status_code_t set_cpu_state (const struct webui_cmd_binding *command, char *args, bool json, bool isv3);
#if WIFI_ENABLE
static status_code_t get_ap_list (const struct webui_cmd_binding *command, char *args, bool json, bool isv3);
#endif
#if FLASHFS_ENABLE
static status_code_t flash_read_file (const struct webui_cmd_binding *command, char *args, bool json, bool isv3);
static status_code_t flash_format (const struct webui_cmd_binding *command, char *args, bool json, bool isv3);
static status_code_t flash_get_capacity (const struct webui_cmd_binding *command, char *args, bool json, bool isv3);
#endif

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
#if SDCARD_ENABLE
    { 200, get_sd_status,      { WebUIAuth_User, WebUIAuth_Admin},  "(json=yes) (<RELEASE|REFRESH>) - display/set SD Card Status" },
    { 210, get_sd_content,     { WebUIAuth_User, WebUIAuth_Admin},  "??" },
    { 220, sd_print,           { WebUIAuth_User, WebUIAuth_Admin},  "??" },
#endif
    { 400, get_settings,       { WebUIAuth_User, WebUIAuth_Admin},  " - display ESP3D settings in JSON" },
    { 401, set_setting,        { WebUIAuth_Admin, WebUIAuth_Admin}, "P=<setting id> T=<type> V=<value> - set specific setting" },
#if WIFI_ENABLE
    { 410, get_ap_list,        { WebUIAuth_User, WebUIAuth_Admin},  "<json=yes> - display available AP list (limited to 30) in plain/JSON" },
#endif
    { 420, get_system_status,  { WebUIAuth_User, WebUIAuth_Admin},  "(json=yes) - display ESP3D current status in plain/JSON" },
    { 444, set_cpu_state,      { WebUIAuth_Admin, WebUIAuth_Admin}, "<RESET|RESTART> - set ESP3D state" },
    { 701, handle_job_status,  { WebUIAuth_Guest, WebUIAuth_Admin}, "(action=<PAUSE|RESUME|ABORT>) - query or control ESP700 stream" },
#if FLASHFS_ENABLE
    { 700, flash_read_file,    { WebUIAuth_User, WebUIAuth_Admin},  "<filename> - read local filesystem file" },
#endif
    { 701, handle_job_status,  { WebUIAuth_Guest, WebUIAuth_Admin}, "(action=<PAUSE|RESUME|ABORT>) - query or control ESP700 stream" },
#if FLASHFS_ENABLE
    { 710, flash_format,       { WebUIAuth_Admin, WebUIAuth_Admin}, "FORMATFS - format local filesystem" },
    { 720, flash_get_capacity, { WebUIAuth_User, WebUIAuth_Admin},  "??" },
#endif
    { 800, get_firmware_spec,  { WebUIAuth_Guest, WebUIAuth_Admin}, "(json=yes) - display FW Informations in plain/JSON" }
};

// NOTE: Returns pointer to the value in a copy of the arguments string.
//       This pointer becomes invalid when the next value is read.
static char *get_arg (char *args, char *arg)
{
    static char *argsp = NULL;

    char *value, *argend;

    if(argsp) {
        free(argsp);
        argsp = NULL;
    }

    if(arg && *arg) {

        if(!(argsp = malloc(strlen(args) + 2)))
            return NULL;

        strcpy(argsp, " ");
        strcat(argsp, args);

        if((value = strstr(argsp, arg)))
            value += strlen(arg);

        if(value && (argend = strchr(value, ' ')))
            *argend = '\0';
    } else
        value = args;

    return value;
}

static bool get_bool_arg (char *args, char *arg)
{
    char *value = get_arg(args, arg);

    if(value)
        strcaps(value);
    else {
        char tmp[16];
        memset(tmp, 0, sizeof(tmp));
        if(get_arg(args, strncpy(tmp, arg, strlen(arg) - 1)))
            return true;
    }

    return value != NULL && (!strcmp(value, "YES") || !strcmp(value, "TRUE") || !strcmp(value, "1"));
}

static bool trim_arg (char *args, char *arg)
{
    char *s1, *s2, *t;

    if((s1 = strstr(args, arg))) {

        if(s1 == args && strlen(args) == strlen(arg)) {
            *args = '\0';
            return true;
        }

        t = s1 + strlen(arg);

        if(s1 > args && *(s1 - 1) != ' ')
            return trim_arg(t, arg);

        if(*t == ' ')
            *t = '\0';
        else if(*t == '=' && (t = strchr(t, ' ')))
            *t = '\0';
        else {
            t = NULL;
            if(s1 > args)
               s1--;
        }

        s2 = s1 + strlen(s1);

        if(t) {
            s2++;
            *t = ' ';
        }

        while(*s2 != '\0')
            *s1++ = *s2++;

        *s1 = '\0';
    }

    return !!s1;
}

status_code_t webui_command_handler (uint32_t command, char *args)
{
    bool json;
    char *end;
    status_code_t status = Status_Unhandled;

//  hal.delay_ms(100, NULL);

    // Trim leading and trailing spaces
    while(*args == ' ')
        args++;

    if((end = args + strlen(args)) != args) {
        while(*(--end) == ' ')
            *end = '\0';
    }
    //

    trim_arg(args, "pwd=");

    json = get_bool_arg(args, " json=");

    trim_arg(args, "json");

    uint32_t i = sizeof(webui_commands) / sizeof(webui_cmd_binding_t);

    while(i) {
        if(webui_commands[--i].id == command) {
            status = webui_commands[i].handler(&webui_commands[i], args, json, client_isv3);
            i = 0;
        }
    }

    get_arg(NULL, NULL); // free any memory allocated for argument parser

    return status;
}

static status_code_t sys_execute (char *cmd)
{
    char syscmd[LINE_BUFFER_SIZE]; // system_execute_line() needs at least this buffer size!

    strcpy(syscmd, cmd);

    return report_status_message(system_execute_line(syscmd));
}

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

static bool json_write_response (cJSON *json)
{
    if(json) {

        char *resp = cJSON_PrintUnformatted(json);

        if(resp) {

            data_is_json();

            hal.stream.write(resp);

            cJSON_free(resp);
        }

        cJSON_Delete(json);
    }

    return !!json;
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

static status_code_t esp_setting (const struct webui_cmd_binding *command, char *args, bool json, bool isv3)
{
    bool ok;
    char response[100];
    cJSON *root = NULL;
    status_code_t status = Status_Unhandled;

    if(command->setting.id != 0) { // straight mapping

        const setting_detail_t *setting = setting_get_details(command->setting.id, NULL);
        bool lookup = setting->datatype == Format_RadioButtons;

        if(*args == '\0') {

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
                    hal.stream.write(strappend(response, 2, svalue, "\n"));
                }
            }
        } else {

            if(command->setting.bit != -1) {
                int32_t mode = strlookup(get_arg(args, NULL), "OFF,ON", ',');
                uint32_t pmask = 1 << command->setting.bit, tmask = get_int_setting_value(setting, 0);
                if(mode >= 0) {
                    if(mode)
                        tmask |= pmask;
                    else
                        tmask ^= pmask;
                    args = uitoa(tmask);
                }
            } else if(lookup) {
                int32_t value = strlookup(args, setting->format, ',');
                if(value != -1)
                    args = uitoa((uint32_t)value);
            }

            sprintf(response, "$%d=%s", command->setting.id, args);
            status = sys_execute(response);

            if(json)
                root = json_create_response_hdr(command->id, false, status == Status_OK, NULL, status == Status_OK ? "ok" : "Set failed");
        }
    } else switch(command->id) {

        case 103: // GetSetSTA_IP:
            status = Status_OK;
            if(*args == '\0') {
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
                    hal.stream.write(response);
                }
            } else {
                char *ip;
                bool found = false;
                if((ip = get_arg(args, " IP=")) && status == Status_OK) {
                    found = true;
                    sprintf(response, "$%d=%s", Setting_IpAddress, ip);
                    status = sys_execute(response);
                }
                if((ip = get_arg(args, " GW=")) && status == Status_OK) {
                    found = true;
                    sprintf(response, "$%d=%s", Setting_Gateway, ip);
                    status = sys_execute(response);
                }
                if((ip = get_arg(args, " MSK=")) && status == Status_OK) {
                    found = true;
                    sprintf(response, "$%d=%s", Setting_NetMask, ip);
                    status = sys_execute(response);
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
        json_write_response(root);

    if(status != Status_OK && !json)
        hal.stream.write("error:setting failure");

    return status;
}

// ESP0
static status_code_t list_commands (const struct webui_cmd_binding *command, char *args, bool json, bool isv3)
{
    bool ok;
    char buf[200];
    int32_t cmd = -1;
    const webui_cmd_binding_t *cmdp = NULL;
    uint32_t i, n = sizeof(webui_commands) / sizeof(webui_cmd_binding_t);
    cJSON *root = NULL;

    if(!(ok = *args == '\0')) {
        cmd = atoi(args);
        for(i = 0; i < n; i++) {
            if(webui_commands[i].id == cmd) {
                cmdp = &webui_commands[i];
                break;
            }
        }

        if(cmdp == NULL)
            strappend(buf, 2, "This command is not supported: ", args);
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
            hal.stream.write(buf);
            hal.stream.write(WEBUI_EOL);
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
        hal.stream.write("[List of ESP3D commands]" WEBUI_EOL);
        for(i = 0; i < n; i++) {
            sprintf(buf, "[ESP%d]%s" WEBUI_EOL, webui_commands[i].id, webui_commands[i].help);
            hal.stream.write(buf);
        }
    }

    if(root)
        json_write_response(root);

    return Status_OK;
}

// Add setting to the JSON response array
static bool add_setting (cJSON *settings, bool isv3, setting_id_t id, int32_t bit, uint_fast16_t offset)
{
    static const char *tmap2[] = { "B", "B", "B", "B", "I", "I", "B", "S", "B", "A", "I", "I" };
    static const char *tmap3[] = { "T", "T", "T", "T", "I", "I", "B", "S", "B", "A", "I", "I" };

    bool ok;
    cJSON *settingobj;
    const setting_detail_t *setting = setting_get_details(id, NULL);

    if((ok = setting && (setting->is_available == NULL || setting->is_available(setting)) && !!(settingobj = cJSON_CreateObject())))
    {
        char opt[50];
        const setting_group_detail_t *group = setting_get_group_details(setting->group);

        if(setting->datatype == Format_Bool)
            bit = 0;

        strcpy(opt, group->name);
        if(isv3) {
            strcat(opt, "/");
            strcat(opt, group->name);
        }
        ok  = !!cJSON_AddStringToObject(settingobj, "F", isv3 ? opt : "network");

        strcpy(opt, uitoa(setting->id));
        if(bit >= 0) {
            strcat(opt, "#");
            strcat(opt, uitoa(bit));
        }
        ok &= !!cJSON_AddStringToObject(settingobj, "P", opt);
        ok &= !!cJSON_AddStringToObject(settingobj, "T", isv3 ? tmap3[setting->datatype] : tmap2[setting->datatype]);
        ok &= !!cJSON_AddStringToObject(settingobj, "V", bit == -1 ? setting_get_value(setting, offset) : get_int_setting_value(setting, offset) & (1 << bit) ? "1" : "0");
        ok &= !!cJSON_AddStringToObject(settingobj, "H", bit == -1 || setting->datatype == Format_Bool ? setting->name : strgetentry(opt, setting->format, bit, ','));
        if(isv3 && setting->reboot_required)
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

// ESP400
static status_code_t get_settings (const struct webui_cmd_binding *command, char *args, bool json, bool isv3)
{
    bool ok;
    cJSON *root = cJSON_CreateObject(), *settings = NULL;

    if((ok = root != NULL) && isv3) {
        ok &= !!cJSON_AddStringToObject(root, "cmd", uitoa(command->id));
        ok &= !!cJSON_AddStringToObject(root, "status", "ok");
    }

    if((ok &= !!(settings = cJSON_AddArrayToObject(root, isv3 ? "data" : "EEPROM")))) {

        add_setting(settings, isv3, Setting_Hostname, -1, 0);
#if HTTP_ENABLE
        add_setting(settings, isv3, Setting_NetworkServices, 2, 0);
        add_setting(settings, isv3, Setting_HttpPort, -1, 0);
#endif
#if TELNET_ENABLE
        add_setting(settings, isv3, Setting_NetworkServices, 0, 0);
        add_setting(settings, isv3, Setting_TelnetPort, -1, 0);
#endif
#if WEBSOCKET_ENABLE
        add_setting(settings, isv3, Setting_NetworkServices, 1, 0);
        add_setting(settings, isv3, Setting_WebSocketPort, -1, 0);
#endif
#if FTP_ENABLE
        add_setting(settings, isv3, Setting_NetworkServices, 3, 0);
        add_setting(settings, isv3, Setting_FtpPort, -1, 0);
#endif
        add_setting(settings, isv3, Setting_IpMode, -1, 0);
//        add_setting(settings, isv3, Setting_ReportInches, -1, 0);
#if ETHERNET_ENABLE
        add_setting(settings, isv3, Setting_IpAddress, -1, 0);
        add_setting(settings, isv3, Setting_Gateway, -1, 0);
        add_setting(settings, isv3, Setting_NetMask, -1, 0);
#endif
#if WIFI_ENABLE
        add_setting(settings, isv3, Setting_WifiMode, -1, 0);

        add_setting(settings, isv3, Setting_WiFi_STA_SSID, -1, 0);
        add_setting(settings, isv3, Setting_WiFi_STA_Password, -1, 0);
        add_setting(settings, isv3, Setting_IpMode, -1, 0);
        add_setting(settings, isv3, Setting_IpAddress, -1, 0);
        add_setting(settings, isv3, Setting_Gateway, -1, 0);
        add_setting(settings, isv3, Setting_NetMask, -1, 0);

        add_setting(settings, isv3, Setting_WiFi_AP_SSID, -1, 0);
        add_setting(settings, isv3, Setting_WiFi_AP_Password, -1, 0);
        add_setting(settings, isv3, Setting_IpAddress2, -1, 0);

#endif
#if BLUETOOTH_ENABLE
//      add_setting(settings, isv3, Setting_WifiMode, -1, 0);
#endif

        json_write_response(root);
        root = NULL;
    }

    if(root)
        cJSON_Delete(root);

    return Status_OK;
}

// ESP401
static status_code_t set_setting (const struct webui_cmd_binding *command, char *args, bool json, bool isv3)
{
    bool ok = false;
    char setting_id[16] = "";
    char *value = get_arg(args, " P=");
    status_code_t status = Status_Unhandled;

    if(value)
        strcpy(setting_id, value);

    value = get_arg(args, " V=");

    if(*setting_id && value) {

        char *bitp, fcmd[LINE_BUFFER_SIZE]; // system_execute_line() needs at least this buffer size!

        // "hack" for bitfield settings
        if((bitp = strchr(setting_id, '#'))) {

            *bitp++ = '\0';
            uint32_t pmask = 1 << atoi(bitp), tmask;

            const setting_detail_t *setting = setting_get_details((setting_id_t)atoi(setting_id), NULL);

            if((ok = (setting = setting_get_details(atoi(setting_id), NULL)))) {

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
            ok = true;

        if(ok) {
            status = Status_OK;
            sprintf(fcmd, "$%s=%s", setting_id, value);
            status = system_execute_line(fcmd);
        }
    }

    if(json) {

        cJSON *root;

        if((ok = !!(root = json_create_response_hdr(command->id, false, status == Status_OK, NULL, status == Status_OK ? "ok" : "Set failed"))))
            json_write_response(root);

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
static status_code_t get_system_status (const struct webui_cmd_binding *command, char *args, bool json, bool isv3)
{
    char buf[200];
    network_info_t *network = networking_get_info();

    if(json) {

        bool ok;
        cJSON *root, *data;

        if((ok = !!(root = json_create_response_hdr(command->id, true, true, &data, NULL)))) {

            ok &= add_system_value(data, "chip id", hal.info);
            ok &= add_system_value(data, "CPU Freq", uitoa(hal.f_step_timer / (1024 * 1024)));

#if SDCARD_ENABLE
            FATFS *fs;
            DWORD fre_clust, used_sect, tot_sect;

            ok &= add_system_value(data, "FS type", "SD");

            if(f_getfree("", &fre_clust, &fs) == FR_OK) {
                tot_sect = (fs->n_fatent - 2) * fs->csize;
                used_sect = tot_sect - fre_clust * fs->csize;
                strcpy(buf, btoa(used_sect << 9)); // assuming 512 byte sector size
                strcat(buf, "/");
                strcat(buf, btoa(tot_sect << 9));
                ok &= add_system_value(data, "FS usage", buf);
            }
#endif

            ok &= add_system_value(data, "wifi", "OFF");
            ok &= add_system_value(data, "ethernet", "ON");
            if(network->status.services.http)
                ok &= add_system_value(data, "HTTP port", uitoa(network->status.http_port));
            if(network->status.services.telnet)
                ok &= add_system_value(data, "Telnet port", uitoa(network->status.telnet_port));
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
            }

#if WEBUI_AUTH_ENABLE
            ok &= add_system_value(data, "authentication", "ON");
#endif
//            ok &= add_system_value(data, "flash", "OFF");
#if SDCARD_ENABLE
            ok &= add_system_value(data, "sd", "ON (FatFS)");
#endif
             ok &= add_system_value(data, "targetfw", "grblHAL");
             strappend(buf, 3, GRBL_VERSION, "-", uitoa(GRBL_BUILD));
             ok &= add_system_value(data, "FW ver", buf);
             ok &= add_system_value(data, "FW arch", hal.board);

             json_write_response(root);
        }

    } else {

        hal.stream.write(strappend(buf, 3, "Processor: ", hal.info, "\n"));
        hal.stream.write(strappend(buf, 3, "CPU Frequency: ", uitoa(hal.f_step_timer / (1024 * 1024)), "Mhz\n"));
        hal.stream.write(strappend(buf, 7, "FW version: ", GRBL_VERSION, "(", uitoa(GRBL_BUILD), ")(", hal.info, ")\n"));
        hal.stream.write(strappend(buf, 3, "Driver version: ", hal.driver_version, "\n"));
        if(hal.board)
            hal.stream.write(strappend(buf, 3, "Board: ", hal.board, "\n"));
    //    hal.stream.write(strappend(buf, 3, "Free memory: ", uitoa(esp_get_free_heap_size()), "\n"));
        hal.stream.write("Baud rate: 115200\n");
        hal.stream.write(strappend(buf, 3, "IP: ", network->status.ip, "\n"));
     #if TELNET_ENABLE
        hal.stream.write(strappend(buf, 3, "Data port: ", uitoa(network->status.telnet_port), "\n"));
     #endif
     #if TELNET_ENABLE
        hal.stream.write(strappend(buf, 3, "Web port: ", uitoa(network->status.http_port), "\n"));
     #endif
     #if WEBSOCKET_ENABLE
        hal.stream.write(strappend(buf, 3, "Websocket port: ", uitoa(network->status.websocket_port), "\n"));
 #endif

    }

    return Status_OK;
}

// ESP701
static status_code_t handle_job_status (const struct webui_cmd_binding *command, char *args, bool json, bool isv3)
{
    bool ok;
    sdcard_job_t *job = sdcard_get_job_info();
    cJSON *root, *data;
    char *action = get_arg(args, " action=");

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
        json_write_response(root);

    return Status_OK;
}

// ESP800
static status_code_t get_firmware_spec (const struct webui_cmd_binding *command, char *args, bool json, bool isv3)
{
    char buf[200];
    network_info_t *network = networking_get_info();

    char *version;

    if((version = get_arg(args, " version=")))
        client_isv3 = *version == '3';

    if(json) {

        bool ok;
        cJSON *root, *data;

        if((ok = !!(root = json_create_response_hdr(command->id, false, true, &data, NULL)))) {

            ok &= !!cJSON_AddStringToObject(data, "FWVersion", GRBL_VERSION);
            ok &= !!cJSON_AddStringToObject(data, "FWTarget", "grbl");
            ok &= !!cJSON_AddStringToObject(data, "FWTargetID", "10");
            ok &= !!cJSON_AddStringToObject(data, "Setup", "Enabled");
            ok &= !!cJSON_AddStringToObject(data, "SDConnection", "direct");
            ok &= !!cJSON_AddStringToObject(data, "SerialProtocol", "Socket");
            ok &= !!cJSON_AddStringToObject(data, "Authentication", "Disabled");
            ok &= !!cJSON_AddStringToObject(data, "WebCommunication", "Synchronous");
            ok &= !!cJSON_AddStringToObject(data, "WebSocketIP", network->status.ip);
            ok &= !!cJSON_AddStringToObject(data, "WebSocketPort", uitoa(network->status.websocket_port));
            ok &= !!cJSON_AddStringToObject(data, "Hostname", network->status.hostname);
            ok &= !!cJSON_AddStringToObject(data, "WebUpdate", "Disabled");
            ok &= !!cJSON_AddStringToObject(data, "FileSystem", "directsd");
            ok &= !!cJSON_AddStringToObject(data, "Time", "none");

            json_write_response(root);
        }
    } else {

        strcpy(buf, "FW version:");
        strcat(buf, GRBL_VERSION);
        strcat(buf, " # FW target:grbl-embedded # FW HW:");
    #if SDCARD_ENABLE
        strcat(buf, "Direct SD");
    #else
        strcat(buf, "No SD");
    #endif
        strcat(buf, " # primary sd:/sd # secondary sd:none # authentication:");
    #if WEBUI_AUTH_ENABLE
        strcat(buf, "yes");
    #else
        strcat(buf, "no");
    #endif
    #if HTTP_ENABLE
        strcat(buf, " # webcommunication: Sync: ");
        strcat(buf, uitoa(network->status.websocket_port));
    #endif
        strcat(buf, " # hostname:");
        strcat(buf, network->status.hostname);
    #if WIFI_SOFTAP
        strcat(buf,"(AP mode)");
    #endif
        strcat(buf, " # axis:");
        strcat(buf, uitoa(N_AXIS));

        hal.stream.write(buf);
    }

    return Status_OK;
}

// ESP111
static status_code_t get_current_ip (const struct webui_cmd_binding *command, char *args, bool json, bool isv3)
{
    char response[20];

    hal.stream.write(strappend(response, 3, args, networking_get_info()->status.ip, "\n"));

    return Status_OK;
}

// ESP200
static status_code_t get_sd_status (const struct webui_cmd_binding *command, char *args, bool json, bool isv3)
{
    char *msg;

    if(*args) {

        bool refresh = !!get_arg(args, " REFRESH"), release = !!get_arg(args, " RELEASE");

        trim_arg(args, "REFRESH"); // Mount?
        trim_arg(args, "RELEASE"); // Unmount?

        msg = *args ? "Unknown parameter" : (release ? "SD card released" : "SD card ok");

    } else
        msg = hal.stream.type == StreamType_SDCard ? "Busy" : (sdcard_getfs() ? "SD card detected" : "Not available");

    if(json)
        json_write_response(json_create_response_hdr(command->id, false, true, NULL, msg));
    else {
        hal.stream.write(msg);
        hal.stream.write(WEBUI_EOL);
    }

    return Status_OK;
}

// ESP210
static status_code_t get_sd_content (const struct webui_cmd_binding *command, char *args, bool json, bool isv3)
{
    status_code_t status = sys_execute("$F");

    return status;
}

// ESP220
static status_code_t sd_print (const struct webui_cmd_binding *command, char *args, bool json, bool isv3)
{
    char response[50];

    status_code_t status = Status_IdleError;
    if(hal.stream.type != StreamType_SDCard) { // Already streaming a file?
        char *cmd = get_arg(args, NULL);
        if(strlen(cmd) > 0) {
            strcpy(response, "$F=");
            strcat(response, cmd);
            status = sys_execute(response);
        }
    }
    hal.stream.write(status == Status_OK ? "ok" : "error:cannot stream file");

    return status;
}


#if WIFI_ENABLE

// ESP410
static status_code_t get_ap_list (const struct webui_cmd_binding *command, char *args, bool json, bool isv3)
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
                json_write_response(root);
            else
                cJSON_Delete(root);
        }
    }

    if(ap_list)
        wifi_release_aplist();

    return Status_OK; // for now
}

#endif

// ESP444
static status_code_t set_cpu_state (const struct webui_cmd_binding *command, char *args, bool json, bool isv3)
{
    status_code_t status = Status_OK;

    char *cmd = get_arg(args, NULL);
    if(!strcmp(cmd, "RESTART") && hal.reboot) {
        hal.stream.write_all("[MSG:Restart ongoing]\r\n");
        hal.delay_ms(1000, hal.reboot); // do the restart after a 1s delay, to allow the response to be sent
    } else
        status = Status_InvalidStatement;

    hal.stream.write(status == Status_OK ? "ok" : "Error:Incorrect Command");

    return status;
}

#if FLASHFS_ENABLE

// ESP700
static status_code_t flash_read_file (const struct webui_cmd_binding *command, char *args, bool json, bool isv3)
{
    status_code_t status = Status_IdleError;

    if(hal.stream.type != StreamType_FlashFs) { // Already streaming a file?
        char *cmd = get_arg(args, NULL);
        if(strlen(cmd) > 0) {
            strcpy(response, "/spiffs");
            strcat(response, cmd);
            status = report_status_message(flashfs_stream_file(response));
        }
    }
    hal.stream.write(status == Status_OK ? "ok" : "error:cannot stream file");

    return status;
}

static status_code_t flash_format (const struct webui_cmd_binding *command, char *args, bool json, bool isv3)
{
    char *cmd = get_arg(args, NULL);
    status_code_t status = Status_InvalidStatement;

    if(!strcmp(cmd, "FORMAT") && esp_spiffs_mounted(NULL)) {
        hal.stream.write("Formating"); // sic
        if(esp_spiffs_format(NULL) == ESP_OK)
            status = Status_OK;
    }
    hal.stream.write(status == Status_OK ? "...Done\n" : "error\n");

    return status;
}

static status_code_t flash_get_capacity (const struct webui_cmd_binding *command, char *args, bool json, bool isv3)
{
    status_code_t status = Status_OK;

    size_t total = 0, used = 0;
    if(esp_spiffs_info(NULL, &total, &used) == ESP_OK) {
        strcpy(response, "SPIFFS  Total:");
        strcat(response, btoa(total));
        strcat(response, " Used:");
        strcat(response, btoa(used));
        hal.stream.write(strcat(response, "\n"));
    } else
        status = Status_InvalidStatement;

    return status;
}

#endif

webui_auth_level_t get_auth_required (uint32_t command, char *args)
{
    webui_auth_level_t level = WebUIAuth_None;

    uint32_t i = sizeof(webui_commands) / sizeof(webui_cmd_binding_t);

    while(i) {
        if(webui_commands[--i].id == command) {
            level = *args ? webui_commands[--i].auth.read : webui_commands[--i].auth.execute;
            i = 0;
        }
    }

    return level;
}

#endif
