/*
  commands_v2.c - An embedded CNC Controller with rs274/ngc (g-code) support

  WebUI backend for https://github.com/luc-github/ESP3D-webui

  Part of grblHAL

  Copyright (c) 2019-2024 Terje Io

  grblHAL is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  grblHAL is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with grblHAL. If not, see <http://www.gnu.org/licenses/>.
*/

#include "driver.h"

#if WEBUI_ENABLE == 1 || WEBUI_ENABLE == 2

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

#include "grbl/vfs.h"
#include "grbl/report.h"
#include "grbl/state_machine.h"

#if SDCARD_ENABLE
#include "sdcard/sdcard.h"
//#include "esp_vfs_fat.h"
#endif

#if WIFI_ENABLE
#include "wifi.h"
#endif

//#include "flashfs.h"

#ifndef LINE_BUFFER_SIZE
#define LINE_BUFFER_SIZE 257 // 256 characters plus terminator
#endif

#define WEBUI_EOL "\n"
#define FIRMWARE_ID "80"
#define FIRMWARE_TARGET "grblHAL"

extern void data_is_json (void);

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
    status_code_t (*handler)(const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file);
    webui_auth_required_t auth;
    const char *help;
    webui_setting_map_t setting;
} webui_cmd_binding_t;

//typedef status_code_t (*webui_command_handler_ptr)(const webui_cmd_binding_t *command, uint_fast16_t argc, char **argv, bool isv3);

static status_code_t esp_setting (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file);
static status_code_t get_settings (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file);
static status_code_t set_setting (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file);
static status_code_t get_system_status (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file);
static status_code_t get_firmware_spec (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file);
static status_code_t get_current_ip (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file);
static status_code_t set_cpu_state (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file);
#if SDCARD_ENABLE
static status_code_t get_sd_status (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file);
static status_code_t get_sd_content (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file);
static status_code_t sd_print (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file);
#endif
#if WIFI_ENABLE
static status_code_t get_ap_list (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file);
#endif
#if FLASHFS_ENABLE
static status_code_t flash_read_file (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file);
static status_code_t flash_format (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file);
static status_code_t flash_get_capacity (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file);
#endif

static const webui_cmd_binding_t webui_commands[] = {
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
  #if BLUETOOTH_ENABLE
    { 140, esp_setting,        { WebUIAuth_Guest, WebUIAuth_Admin}, "??", { Setting_BlueToothServiceName, -1 } },
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
// Action commands
#if SDCARD_ENABLE
    { 200, get_sd_status,      { WebUIAuth_User, WebUIAuth_Admin},  "(json=yes) (<RELEASE|REFRESH>) - display/set SD Card Status" },
    { 210, get_sd_content,     { WebUIAuth_User, WebUIAuth_Admin},  "??" },
    { 220, sd_print,           { WebUIAuth_User, WebUIAuth_Admin},  "??" },
#endif
    { 400, get_settings,       { WebUIAuth_User, WebUIAuth_Admin},  " - display ESP3D settings in JSON" },
    { 401, set_setting,        { WebUIAuth_Admin, WebUIAuth_Admin}, "P=<setting id> T=<type> V=<value> - set specific setting" },
#if WIFI_ENABLE
    { 410, get_ap_list,        { WebUIAuth_User, WebUIAuth_Admin},  "(json=yes) - display available AP list (limited to 30) in plain/JSON" },
#endif
    { 420, get_system_status,  { WebUIAuth_User, WebUIAuth_Admin},  "(json=yes) - display ESP3D current status in plain/JSON" },
    { 444, set_cpu_state,      { WebUIAuth_Admin, WebUIAuth_Admin}, "<RESET|RESTART> - set ESP3D state" },
#if FLASHFS_ENABLE
    { 700, flash_read_file,    { WebUIAuth_User, WebUIAuth_Admin},  "<filename> - read local filesystem file" },
#endif
#if FLASHFS_ENABLE
    { 710, flash_format,       { WebUIAuth_Admin, WebUIAuth_Admin}, "FORMATFS - format local filesystem" },
    { 720, flash_get_capacity, { WebUIAuth_User, WebUIAuth_Admin},  "??" },
#endif
    { 800, get_firmware_spec,  { WebUIAuth_Guest, WebUIAuth_Guest}, "(json=yes) - display FW Informations in plain/JSON" }
};

status_code_t webui_v2_command_handler (uint32_t command, uint_fast16_t argc, char **argv, webui_auth_level_t auth_level, vfs_file_t *file)
{
    status_code_t status = Status_Unhandled;

//  hal.delay_ms(100, NULL);

    webui_trim_arg(&argc, argv, "pwd=");

    webui_trim_arg(&argc, argv, "json");
    webui_trim_arg(&argc, argv, "json=");

    uint32_t i = sizeof(webui_commands) / sizeof(webui_cmd_binding_t);

    while(i) {
        if(webui_commands[--i].id == command) {
#if xWEBUI_AUTH_ENABLE
            if(auth_level < (argc == 0 ? webui_commands[i].auth.read : webui_commands[i].auth.execute)) {
                if(json)
                    json_write_response(json_create_response_hdr(webui_commands[i].id, false, true, NULL, "Wrong authentication level"), file);
                else
                    vfs_puts("Wrong authentication level" ASCII_EOL, file);

                status = auth_level < WebUIAuth_User ? Status_AuthenticationRequired : Status_AccessDenied;
            } else
#endif
            status = webui_commands[i].handler(&webui_commands[i], argc, argv, file);
            i = 0;
        }
    }

    return status;
}

// Shared functions

static vfs_file_t *fwd_file;
static on_stream_changed_ptr on_stream_changed = NULL;
static stream_write_ptr pre_stream = NULL;

static void stream_forward (const char *s)
{
    vfs_puts(s, fwd_file);
}

static void stream_changed (stream_type_t type)
{
    if(on_stream_changed)
        on_stream_changed(type);

    if(type != StreamType_File && hal.stream.write == stream_forward) {
        hal.stream.write = pre_stream;
        pre_stream = NULL;
    }
}

static bool json_write_response (cJSON *json, vfs_file_t *file)
{
    bool ok = false;

    if(json) {

        char *resp = cJSON_PrintUnformatted(json);

        if((ok = !!resp)) {
            cJSON_Delete(json);
            data_is_json();
            vfs_puts(resp, file);
            cJSON_free(resp);
        } else
            cJSON_Delete(json);
    }

    return ok;
}

static status_code_t sys_execute (char *cmd, vfs_file_t *file)
{
    status_code_t status;
    char syscmd[LINE_BUFFER_SIZE]; // system_execute_line() needs at least this buffer size!

    if(on_stream_changed == NULL) {
        on_stream_changed = grbl.on_stream_changed;
        grbl.on_stream_changed = stream_changed;
    }

    pre_stream = hal.stream.write;
    hal.stream.write = stream_forward;

    strcpy(syscmd, cmd);
    status = system_execute_line(syscmd);

    if(pre_stream) {
        hal.stream.write = pre_stream;
        pre_stream = NULL;
    }

    return status;
}

// ESP100 - ESP181 except ESP111 and ESP140

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

static status_code_t esp_setting (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file)
{
    char response[100];
    status_code_t status = Status_Unhandled;

    if(command->setting.id != 0) { // straight mapping

        const setting_detail_t *setting = setting_get_details(command->setting.id, NULL);
        bool lookup = setting->datatype == Format_RadioButtons;

        if(argc == 0) {

            uint32_t value;
            char buf[100], *svalue;

            if(setting) {
                status = Status_OK;
                value = command->setting.bit == -1 ? setting_get_int_value(setting, 0) : ((setting_get_int_value(setting, 0) & (1 << command->setting.bit)) ? 1 : 0);
                svalue = lookup ? strgetentry(buf, setting->format, value, ',') : (command->setting.bit == -1 ? strcpy(buf, setting_get_value(setting, 0)) : (value ? "ON" : "OFF"));
            }

            if(setting) {
                status = Status_OK;
                vfs_puts(strappend(response, 2, svalue, WEBUI_EOL), file);
            }

        } else {

            char *param = argv[0];

            if(command->setting.bit != -1) {
                int32_t mode = strlookup(param, "OFF,ON", ',');
                uint32_t pmask = 1 << command->setting.bit, tmask = setting_get_int_value(setting, 0);
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
        }
    } else switch(command->id) {

        case 103: // GetSetSTA_IP:
            status = Status_OK;
            if(argc == 0) {
                char ip[16], gw[16], mask[16];
                sprintf(response, "IP:%s, GW:%s, MSK:%s\n", get_setting_value(ip, Setting_IpAddress), get_setting_value(gw, Setting_Gateway), get_setting_value(mask, Setting_NetMask));
                vfs_puts(response, file);
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
            }
            break;

        default:
            break;
    }

    if(status != Status_OK)
        vfs_puts("error:setting failure", file);

    return status;
}

// Add setting to the JSON response array
static bool add_setting (cJSON *settings, setting_id_t id, int32_t bit, uint_fast16_t offset)
{
    static const char *tmap2[] = { "B", "B", "B", "B", "I", "I", "B", "S", "S", "A", "I", "I" };

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

        ok  = !!cJSON_AddStringToObject(settingobj, "F", "network");

        strcpy(opt, uitoa(setting->id));
        if(bit >= 0) {
            strcat(opt, "#");
            strcat(opt, uitoa(bit));
        }
        ok &= !!cJSON_AddStringToObject(settingobj, "P", opt);
        ok &= !!cJSON_AddStringToObject(settingobj, "T", tmap2[setting->datatype]);
        ok &= !!cJSON_AddStringToObject(settingobj, "V", bit == -1 ? setting_get_value(setting, offset) : setting_get_int_value(setting, offset) & (1 << bit) ? "1" : "0");
        ok &= !!cJSON_AddStringToObject(settingobj, "H", bit == -1 || setting->datatype == Format_Bool ? setting->name : strgetentry(opt, setting->format, bit, ','));

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


// ESP111
static status_code_t get_current_ip (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file)
{
    char response[20];

    vfs_puts(strappend(response, 3, argv[0], networking_get_info()->status.ip, WEBUI_EOL), file);

    return Status_OK;
}

#if SDCARD_ENABLE

// ESP200
static status_code_t get_sd_status (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file)
{
    char *msg;

    if(argc == 1) {

        bool refresh = !!webui_get_arg(argc, argv, "REFRESH"), release = !!webui_get_arg(argc, argv, "RELEASE");

        UNUSED(refresh);

        webui_trim_arg(&argc, argv, "REFRESH"); // Mount?
        webui_trim_arg(&argc, argv, "RELEASE"); // Unmount?

        msg = argc ? "Unknown parameter" : (release ? "SD card released" : "SD card ok");

    } else
        msg = hal.stream.type == StreamType_File ? "Busy" : (sdcard_getfs() ? "SD card detected" : "Not available");

    vfs_puts(msg, file);
    vfs_puts(WEBUI_EOL, file);

    return Status_OK;
}

// ESP210
static status_code_t get_sd_content (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file)
{
    status_code_t status = sys_execute("$F", file);

    return status;
}

// ESP220
static status_code_t sd_print (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file)
{
    status_code_t status = Status_IdleError;

    if(hal.stream.type != StreamType_File) { // Already streaming a file?
        char *cmd = webui_get_arg(argc, argv, NULL);
        if(strlen(cmd) > 0)
            status = stream_file(state_get(), cmd);
    }

    vfs_puts(status == Status_OK ? "ok" : "error:cannot stream file", file);

    return status;
}

#endif

// ESP400
static status_code_t get_settings (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file)
{
    bool ok;
    cJSON *root = cJSON_CreateObject(), *settings = NULL;

    ok = root != NULL;

    if((ok &= !!(settings = cJSON_AddArrayToObject(root, "EEPROM")))) {

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

// ESP401
static status_code_t set_setting (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file)
{
    bool ok = false;
    char *setting_id = webui_get_arg(argc, argv, "P=");
    char *value = webui_get_arg(argc, argv, "V=");
    status_code_t status = Status_Unhandled;

    if(setting_id && value) {

        char *bitp, fcmd[LINE_BUFFER_SIZE]; // system_execute_line() needs at least this buffer size!

        // "hack" for bitfield settings
        if((bitp = strchr(setting_id, '#'))) {

            *bitp++ = '\0';
            uint32_t pmask = 1 << atoi(bitp), tmask;

            const setting_detail_t *setting = setting_get_details((setting_id_t)atoi(setting_id), NULL);

            if((ok = (setting = setting_get_details(atoi(setting_id), NULL)))) {

                tmask = setting_get_int_value(setting, 0);

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

    grbl.report.status_message(status);

    return status;
}

#if WIFI_ENABLE

// ESP410
static status_code_t get_ap_list (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file)
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

// ESP420
static status_code_t get_system_status (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file)
{
    char buf[200];
    network_info_t *network = networking_get_info();

    vfs_puts(strappend(buf, 3, "Processor: ", hal.info, WEBUI_EOL), file);
    if(hal.get_free_mem)
        vfs_puts(strappend(buf, 3, "free mem", btoa(hal.get_free_mem()), WEBUI_EOL), file);
    vfs_puts(strappend(buf, 3, "CPU Frequency: ", uitoa(hal.f_mcu ? hal.f_mcu : hal.f_step_timer / 1000000UL), "MHz" WEBUI_EOL), file);
    vfs_puts(strappend(buf, 7, "FW version: ", GRBL_VERSION, "(", uitoa(GRBL_BUILD), ")(", hal.info, ")" WEBUI_EOL), file);
    vfs_puts(strappend(buf, 3, "Driver version: ", hal.driver_version, WEBUI_EOL), file);
    if(hal.board)
        vfs_puts(strappend(buf, 3, "Board: ", hal.board, WEBUI_EOL), file);
//    vfs_puts(strappend(buf, 3, "Free memory: ", uitoa(esp_get_free_heap_size()), WEBUI_EOL));
    vfs_puts("Baud rate: 115200\n", file);
    vfs_puts(strappend(buf, 3, "IP: ", network->status.ip, WEBUI_EOL), file);
#if TELNET_ENABLE
    vfs_puts(strappend(buf, 3, "Data port: ", uitoa(network->status.telnet_port), WEBUI_EOL), file);
#endif
#if TELNET_ENABLE
    vfs_puts(strappend(buf, 3, "Web port: ", uitoa(network->status.http_port), WEBUI_EOL), file);
#endif
#if WEBSOCKET_ENABLE
    vfs_puts(strappend(buf, 3, "Websocket port: ", uitoa(network->status.websocket_port), WEBUI_EOL), file);
#endif

    return Status_OK;
}

// ESP444
static status_code_t set_cpu_state (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file)
{
    status_code_t status = Status_OK;

    char *cmd = webui_get_arg(argc, argv, NULL);
    if(!strcmp(cmd, "RESTART") && hal.reboot) {
        hal.stream.write_all("[MSG:Restart ongoing]\r\n");
        hal.delay_ms(1000, hal.reboot); // do the restart after a 1s delay, to allow the response to be sent
    } else
        status = Status_InvalidStatement;

    vfs_puts(status == Status_OK ? "ok" : "Error:Incorrect Command", file);

    return status;
}

#if FLASHFS_ENABLE

// ESP700
static status_code_t flash_read_file (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file)
{
    status_code_t status = Status_IdleError;

    if(hal.stream.type != StreamType_File) { // Already streaming a file?
        char *cmd = webui_get_arg(argc, argv, NULL);
        if(strlen(cmd) > 0) {
            strcpy(response, "/spiffs");
            strcat(response, cmd);
            status = stream_file(state_get(), cmd);
        }
    }
    vfs_puts(status == Status_OK ? "ok" : "error:cannot stream file", file);

    return status;
}

// ESP710
static status_code_t flash_format (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file)
{
    char *cmd = webui_get_arg(argc, argv, NULL);
    status_code_t status = Status_InvalidStatement;

    if(!strcmp(cmd, "FORMAT") && esp_spiffs_mounted(NULL)) {
        vfs_puts("Formating", file); // sic
        if(esp_spiffs_format(NULL) == ESP_OK)
            status = Status_OK;
    }
    vfs_puts(status == Status_OK ? "...Done\n" : "error\n", file, file);

    return status;
}

// ESP720
static status_code_t flash_get_capacity (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file)
{
    status_code_t status = Status_OK;

    size_t total = 0, used = 0;
    if(esp_spiffs_info(NULL, &total, &used) == ESP_OK) {
        strcpy(response, "SPIFFS  Total:");
        strcat(response, btoa(total));
        strcat(response, " Used:");
        strcat(response, btoa(used));
        vfs_puts(strcat(response, WEBUI_EOL), file);
    } else
        status = Status_InvalidStatement;

    return status;
}

#endif // FLASHFS_ENABLE

// ESP800
static status_code_t get_firmware_spec (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, vfs_file_t *file)
{
    char buf[200];
    network_info_t *network = networking_get_info();

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

    vfs_puts(buf, file);

    return Status_OK;
}

#endif // WEBUI_ENABLE
