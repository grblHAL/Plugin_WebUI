/*
  webui/commands.c - An embedded CNC Controller with rs274/ngc (g-code) support

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

#include "driver.h"

#if WEBUI_ENABLE

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#include "../networking/websocketd.h"
#include "../networking/urldecode.h"
#include "../networking/utils.h"
#include "../networking/strutils.h"
#include "../networking/cJSON.h"

#include "server.h"

#include "grbl/report.h"

#if SDCARD_ENABLE
#include "sdcard/sdcard.h"
//#include "esp_vfs_fat.h"
#endif

//#include "flashfs.h"

#ifndef LINE_BUFFER_SIZE
#define LINE_BUFFER_SIZE 257 // 256 characters plus terminator
#endif

extern void data_is_json (void);

typedef enum {
    WebUICmd_GetSetSTA_SSID = 100,
    WebUICmd_GetSetSTA_Password = 101,
    WebUICmd_GetSetSTA_IPMode = 102,
    WebUICmd_GetSetSTA_IP = 103,
    WebUICmd_GetSetAP_SSID = 105,
    WebUICmd_GetSetAP_Password = 106,
    WebUICmd_GetSetAP_IP = 107,
    WebUICmd_GetSetAP_Channel = 108,
    WebUICmd_GetSetRadioMode = 110,
    WebUICmd_GetCurrentIP = 111,
    WebUICmd_GetSetHostname = 112,
    //WebUICmd_GetSetRadioOnOff = 115,
    WebUICmd_GetSetHTTPOnOff = 120,
    WebUICmd_GetSetHttpPort = 121,
    WebUICmd_GetSetTelnetOnOff = 130,
    WebUICmd_GetSetTelnetPort = 131,
    WebUICmd_GetSetBluetoothName = 140,
    WebUICmd_GetSDCardStatus = 200,
    WebUICmd_GetSDCardContent = 210,
    //WebUICmd_DeleteSDCardFile = 215,
    WebUICmd_PrintSD = 220,
    WebUICmd_GetSettings = 400,
    WebUICmd_SetEEPROMSetting = 401,
    WebUICmd_GetAPList = 410,
    WebUICmd_GetStatus = 420,
    WebUICmd_Reboot = 444,
    //WebUICmd_SetUserPassword = 555,
    //WebUICmd_SendMessage = 600,
    //WebUICmd_GetSetNotifications = 600,
    WebUICmd_ReadLocalFile = 700,
    WebUICmd_FormatFlashFS = 710,
    WebUICmd_GetFlashFSCapacity = 720,
    WebUICmd_GetFirmwareSpec = 800
} webui_cmd_t;

typedef enum {
    WebUIType_IPAddress = 'A',
    WebUIType_Boolean = 'B',
    WebUIType_Flag = 'F',
    WebUIType_Integer = 'I',
    WebUIType_String = 'S'
} webui_stype_t;

typedef struct {
    webui_cmd_t command;
    setting_id_t setting;
    int8_t bit;
} webui_setting_map_t;

static const webui_setting_map_t setting_map[] = {
#if WIFI_ENABLE
    { .command = WebUICmd_GetSetSTA_SSID,      .setting = Setting_WiFi_STA_SSID, .bit = -1 },
    { .command = WebUICmd_GetSetSTA_Password,  .setting = Setting_WiFi_STA_Password, .bit = -1 },
    { .command = WebUICmd_GetSetSTA_IPMode,    .setting = 0, .bit = -1 },
    { .command = WebUICmd_GetSetSTA_IP,        .setting = 0, .bit = -1 },
    { .command = WebUICmd_GetSetAP_SSID,       .setting = Setting_WiFi_AP_SSID, .bit = -1 },
    { .command = WebUICmd_GetSetAP_Password,   .setting = Setting_WiFi_AP_Password, .bit = -1 },
    { .command = WebUICmd_GetSetAP_IP,         .setting = Setting_IpAddress2, .bit = -1 },
    { .command = WebUICmd_GetSetAP_Channel,    .setting = Setting_Wifi_AP_Channel, .bit = -1 },
    { .command = WebUICmd_GetSetRadioMode,     .setting = 0, .bit = -1 },
#else
    { .command = WebUICmd_GetSetSTA_IPMode,    .setting = Setting_IpMode, .bit = -1 },
    { .command = WebUICmd_GetSetSTA_IP,        .setting = Setting_IpAddress, .bit = -1 },
#endif
    { .command = WebUICmd_GetSetHostname,      .setting = Setting_Hostname, .bit = -1 },
    { .command = WebUICmd_GetSetHTTPOnOff,     .setting = Setting_NetworkServices, .bit = 2 },
    { .command = WebUICmd_GetSetHttpPort,      .setting = Setting_HttpPort, .bit = -1 },
    { .command = WebUICmd_GetSetTelnetOnOff,   .setting = Setting_NetworkServices, .bit = 0 },
    { .command = WebUICmd_GetSetTelnetPort,    .setting = Setting_TelnetPort, .bit = -1 },
#if BLUETOOTH_ENABLE
    { .command = WebUICmd_GetSetBluetoothName, .setting = Setting_BlueToothServiceName, .bit = -1 }
#endif
};

static char *get_arg (char *args, char *arg, bool spacedelimited)
{
    static char *argsp = NULL, *argsm = NULL;

    char *value;

    if(args != argsp || arg == NULL) {
        if(argsm) {
            free(argsm);
            argsm = NULL;
        }
        if((argsp = args)) {
            if(!(argsm = malloc(strlen(args) + 1)))
                return NULL;
            strcpy(argsm, args);
        }
    }

    if(arg && *arg) {

        size_t len = strlen(arg);

        if(!strncmp(argsm, &arg[1], len - 1))
            value = &args[len - 1];
        else if((value = strstr(argsm, arg)))
            value = &args[value - argsm + len];

        if(value) {
            char *end;
            bool ispwd = !strcmp(arg, " pwd=");
            if((end = spacedelimited ? strchr(value, ' ') : !ispwd ? strstr(value, arg) : NULL))
                *end = '\0';
        }

    } else
        value = args;

    return value;
}


// add file to the JSON response array
static bool add_setting (cJSON *settings, setting_id_t p, char t, int32_t bit, char *v, char *h, char *s, char *m)
{
    bool ok = true;

    cJSON *setting;

    if((ok = (setting = cJSON_CreateObject()) != NULL))
    {
        char ps[12], ts[2];

        strcpy(ps, uitoa(p));

        if(bit >= 0) {
            strcat(ps, "#");
            strcat(ps, uitoa(bit));
        }

        ts[0] = t;
        ts[1] = '\0';

        ok  = cJSON_AddStringToObject(setting, "F", "network") != NULL;
        ok &= cJSON_AddStringToObject(setting, "P", ps) != NULL;
        ok &= cJSON_AddStringToObject(setting, "T", ts) != NULL;
        ok &= cJSON_AddStringToObject(setting, "V", v) != NULL;
        ok &= cJSON_AddStringToObject(setting, "H", h) != NULL;

        switch(t) {

            case WebUIType_Boolean:
            case WebUIType_Flag:
                {
                    uint32_t i, j = strnumentries(s, ',');
                    char opt[20], val[20];
                    cJSON *option, *options = cJSON_AddArrayToObject(setting, "O");

                    for(i = 0; i < j; i++) {
                        option = cJSON_CreateObject();
                        cJSON_AddStringToObject(option, strgetentry(opt, s, i, ','), strgetentry(val, m, i, ','));
                        cJSON_AddItemToArray(options, option);
                    }
                }
                break;

            case WebUIType_IPAddress:
                break;

            default:
                ok &= cJSON_AddStringToObject(setting, "S", s) != NULL;
                ok &= cJSON_AddStringToObject(setting, "M", m) != NULL;
                break;

        }
        if(ok)
            cJSON_AddItemToArray(settings, setting);
    }

    return ok;
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

network_settings_t *get_network_settings (void)
{
    static network_settings_t settings = {0};

    char value[40];

    if(get_setting_value(value, Setting_Hostname))
        strcpy(settings.hostname, value);
    if(get_setting_value(value, Setting_IpAddress))
        strcpy(settings.ip, value);
    if(get_setting_value(value, Setting_Gateway))
        strcpy(settings.gateway, value);
    if(get_setting_value(value, Setting_NetMask))
        strcpy(settings.mask, value);
    if(get_setting_value(value, Setting_TelnetPort))
        settings.telnet_port = atoi(value);
    if(get_setting_value(value, Setting_HttpPort))
        settings.http_port = atoi(value);
    if(get_setting_value(value, Setting_WebSocketPort))
        settings.websocket_port = atoi(value);
    if(get_setting_value(value, Setting_NetworkServices))
        settings.services.mask = atoi(value);

    return &settings;
}

static bool get_settings (void)
{
//    list_settings_webui(NULL, NULL);
//    return true;

    bool ok;

    cJSON *root = cJSON_CreateObject(), *settings = NULL;

    if((ok = (root && (settings = cJSON_AddArrayToObject(root, "EEPROM"))))) {

        network_settings_t *network = get_network_settings();

//        hal.stream.write_is_json();

        add_setting(settings, Setting_Hostname, WebUIType_String, -1, network->hostname, "Hostname", "33", "1");
  #if HTTP_ENABLE
        add_setting(settings, Setting_NetworkServices, WebUIType_Boolean, 2, uitoa(network->services.http), "HTTP protocol", "Enabled,Disabled", "1,0");
        add_setting(settings, Setting_HttpPort, WebUIType_Integer, -1, uitoa(network->http_port), "HTTP Port", "65535", "1");
  #endif
  #if TELNET_ENABLE
        add_setting(settings, Setting_NetworkServices, WebUIType_Boolean, 0, uitoa(network->services.telnet), "Telnet protocol", "Enabled,Disabled", "1,0");
        add_setting(settings, Setting_TelnetPort, WebUIType_Integer, -1, uitoa(network->telnet_port), "Telnet Port", "65535", "1");
  #endif

#if WIFI_ENABLE
        add_setting(settings, Setting_WifiMode, WebUIType_Boolean, -1, uitoa(wifi->mode), "Radio mode", "None,STA,AP", "0,1,2");

        add_setting(settings, Setting_WiFi_STA_SSID, WebUIType_String, -1, wifi->sta.ssid, "Station SSID", "32", "1");
        add_setting(settings, Setting_WiFi_STA_Password, WebUIType_String, -1, HIDDEN_PASSWORD, "Station Password", "64", "1");
        add_setting(settings, Setting_IpMode, WebUIType_Boolean, -1, uitoa(settings->ip_mode), "Station IP Mode", "DHCP,Static", "1,0");
        add_setting(settings, Setting_IpAddress, WebUIType_IPAddress, -1, iptoa(&settings->ip), "Station Static IP", "", "");
        add_setting(settings, Setting_Gateway, WebUIType_IPAddress, -1, iptoa(&settings->gateway), "Station Static Gateway", "", "");
        add_setting(settings, Setting_NetMask, WebUIType_IPAddress, -1, iptoa(&settings->mask), "Station Static Mask", "", "");

        add_setting(settings, Setting_WiFi_AP_SSID, WebUIType_String, -1, wifi->ap.ssid, "AP SSID", "32", "1");
        add_setting(settings, Setting_WiFi_AP_Password, WebUIType_String, -1, HIDDEN_PASSWORD, "AP Password", "64", "1");
        add_setting(settings, Setting_IpAddress2, WebUIType_IPAddress, -1, iptoa(&settings->ip), "AP Static IP", "", "");

#endif
#if BLUETOOTH_ENABLE
//      add_setting(settings, Setting_WifiMode, WebUIType_Boolean, -1, uitoa(wifi->mode), "Radio mode", "None,BT", "0,1");
#endif

        char *resp = cJSON_PrintUnformatted(root);

        if(resp) {

            data_is_json();

            hal.stream.write(resp);

            cJSON_free(resp);
        }
    }

    if(root)
        cJSON_Delete(root);

    return ok;
}

static void set_setting (char *args)
{
    status_code_t status = Status_Unhandled;
    char *setting = get_arg(args, " P=", true);
    char *value = get_arg(args, " V=", false);

    if(setting && value) {

        char *bitp, fcmd[LINE_BUFFER_SIZE]; // system_execute_line() needs at least this buffer size!

        // "hack" for bitfield settings
        if((bitp = strchr(setting, '#'))) {

            *bitp++ = '\0';
            uint32_t pmask = 1 << atoi(bitp), tmask;
            bool ok = false;
            network_settings_t *settings = get_network_settings();

            switch(atoi(setting)) {

                case Setting_NetworkServices:
                    ok = true;
                    tmask = settings->services.mask;
                    break;

                default:
                    break;
            }

            if(ok) {
                if(*value == '0')
                    tmask ^= pmask;
                else
                    tmask |= pmask;
                value = uitoa(tmask);
            } // else report error?
        }

        sprintf(fcmd, "$%s=%s", setting, value);

        status = report_status_message(system_execute_line(fcmd));
    }

    hal.stream.write(status == Status_OK ? "ok" : "Invalid or unknown setting");
}

static bool get_system_status (void)
{
    char buf[200];
    network_settings_t *settings = get_network_settings();

    hal.stream.write(strappend(buf, 3, "Processor: ", hal.info, "\n"));
    hal.stream.write(strappend(buf, 3, "CPU Frequency: ", uitoa(hal.f_step_timer / (1024 * 1024)), "Mhz\n"));
    hal.stream.write(strappend(buf, 7, "FW version: ", GRBL_VERSION, "(", uitoa(GRBL_BUILD), ")(", hal.info, ")\n"));
    hal.stream.write(strappend(buf, 3, "Driver version: ", hal.driver_version, "\n"));
    if(hal.board)
        hal.stream.write(strappend(buf, 3, "Board: ", hal.board, "\n"));
//    hal.stream.write(strappend(buf, 3, "Free memory: ", uitoa(esp_get_free_heap_size()), "\n"));
    hal.stream.write("Baud rate: 115200\n");
//    hal.stream.write(strappend(buf, 3, "IP: ", wifi_get_ipaddr(), "\n"));
 #if TELNET_ENABLE
    hal.stream.write(strappend(buf, 3, "Data port: ", uitoa(settings->telnet_port), "\n"));
 #endif
 #if TELNET_ENABLE
    hal.stream.write(strappend(buf, 3, "Web port: ", uitoa(settings->http_port), "\n"));
 #endif
 #if WEBSOCKET_ENABLE
    hal.stream.write(strappend(buf, 3, "Websocket port: ", uitoa(settings->websocket_port), "\n"));
 #endif

    return true;
}

static bool get_firmware_spec (void)
{
    char buf[200];
    network_settings_t *settings = get_network_settings();

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
    strcat(buf, uitoa(settings->websocket_port));
#endif
    strcat(buf, "# hostname:");
    strcat(buf, settings->hostname);
#if WIFI_SOFTAP
    strcat(buf,"(AP mode)");
#endif

    hal.stream.write(buf);

    return true;
}

#if WIFI_ENABLE

static bool get_ap_list (void)
{
    bool ok = false;

    ap_list_t *ap_list = wifi_get_aplist();

    if(ap_list && ap_list->ap_records) {

        cJSON *root;

        if((root = cJSON_CreateObject())) {

            cJSON *ap, *aps;

            if((aps = cJSON_AddArrayToObject(root, "AP_LIST"))) {

                for(int i = 0; i < ap_list->ap_num; i++) {
                    if((ok = (ap = cJSON_CreateObject()) != NULL))
                    {
                        ok = cJSON_AddStringToObject(ap, "SSID", (char *)ap_list->ap_records[i].ssid) != NULL;
                        ok &= cJSON_AddNumberToObject(ap, "SIGNAL",  (double)ap_list->ap_records[i].rssi) != NULL;
                        ok &= cJSON_AddStringToObject(ap, "IS_PROTECTED", ap_list->ap_records[i].authmode == WIFI_AUTH_OPEN ? "0" : "1") != NULL;
                        if(ok)
                            cJSON_AddItemToArray(aps, ap);
                    }
                }
            }

            if(ok) {
                char *resp = cJSON_PrintUnformatted(root);
                hal.stream.write(resp);
                free(resp);
            }

            if(root)
                cJSON_Delete(root);
        }
    }

    if(ap_list)
        wifi_release_aplist();

    return ok;
}

#endif

static status_code_t sys_execute (char *cmd)
{
    char syscmd[LINE_BUFFER_SIZE]; // system_execute_line() needs at least this buffer size!

    strcpy(syscmd, cmd);

    return report_status_message(system_execute_line(syscmd));
}

status_code_t webui_command_handler (uint32_t command, char *args)
{
    status_code_t status = Status_OK;
    char response[100];

//  hal.delay_ms(100, NULL);

    if(command < 200 && command != WebUICmd_GetCurrentIP) { // Handle setting

        const webui_setting_map_t *map = NULL;
        uint32_t i = sizeof(setting_map) / sizeof(webui_setting_map_t);

        while(i && map == NULL) {
            if(setting_map[--i].command == command)
                map = &setting_map[i];
        }

        if(map) {

            network_settings_t *network = get_network_settings();

            status = Status_Unhandled;

            if(map->setting != 0 && map->bit == -1) { // straight mapping
                if(*args == '\0') {

                    char buf[100], *value;

                    if((value = get_setting_value(buf, map->setting))) {
                        status = Status_OK;
                        hal.stream.write(strappend(response, 2, value, "\n"));
                    }
                } else {
                    sprintf(response, "$%d=%s", map->setting, args);
                    status = sys_execute(response);
                }
            } else switch(map->command) {

                case WebUICmd_GetSetSTA_IPMode:
                    if(*args == '\0') {
                        char mode[7];
                        strgetentry(mode, "STATIC,DHCP,AUTOIP", network->ip_mode, ',');
                        hal.stream.write(strappend(response, 2, mode, "\n"));
                        status = Status_OK;
                    } else {
                        int32_t mode = strlookup(get_arg(args, NULL, true), "STATIC,DHCP,AUTOIP", ',');
                        if(mode >= 0) {
                            sprintf(response, "$%d=%d", Setting_IpMode, (int16_t)mode);
                            status = sys_execute(response);
                        }
                    }
                    break;

                case WebUICmd_GetSetSTA_IP:
                    {
                        status = Status_OK;
                        if(*args == '\0') {
                            char ip[16], gw[16], mask[16];
                            sprintf(response, "IP:%s, GW:%s, MSK:%s\n", get_setting_value(ip, Setting_IpAddress), get_setting_value(gw, Setting_Gateway), get_setting_value(mask, Setting_NetMask));
                            hal.stream.write(response);
                        } else {
                            char *ip;
                            bool found = false;
                            if((ip = get_arg(args, " IP=", true)) && status == Status_OK) {
                                found = true;
                                sprintf(response, "$%d=%s", Setting_IpAddress, ip);
                                status = sys_execute(response);
                            }
                            if((ip = get_arg(args, " GW=", true)) && status == Status_OK) {
                                found = true;
                                sprintf(response, "$%d=%s", Setting_Gateway, ip);
                                status = sys_execute(response);
                            }
                            if((ip = get_arg(args, " MSK=", true)) && status == Status_OK) {
                                found = true;
                                sprintf(response, "$%d=%s", Setting_NetMask, ip);
                                status = sys_execute(response);
                            }
                            if(!found)
                                status = Status_Unhandled;
                        }
                    }
                    break;

#if WIFI_ENABLE
                case WebUICmd_GetSetRadioMode:
                    if(*args == '\0') {
                        char mode[6];
                        strgetentry(mode, "OFF,STA,AP,APSTA", network->mode, ',');
                        hal.stream.write(strappend(response, 2, mode, "\n"));
                        status = Status_OK;
                    } else {
                        int32_t mode = strlookup(get_arg(args, NULL, true), "OFF,STA,AP,APSTA", ',');
                        if(mode >= 0) {
                            sprintf(response, "$%d=%d", Setting_WifiMode, mode);
                            status = sys_execute(response);
                        }
                    }

                    break;
#endif

                case WebUICmd_GetSetHTTPOnOff:
                case WebUICmd_GetSetTelnetOnOff:
                    {
                        uint32_t pmask = 1 << map->bit, tmask = network->services.mask;
                        if(*args == '\0') {
                            status = Status_OK;
                            hal.stream.write(strappend(response, 2, network->services.mask & pmask ? "ON" : "OFF", "\n"));
                        } else {
                            int32_t mode = strlookup(get_arg(args, NULL, true), "OFF,ON", ',');
                            if(mode >= 0) {
                                if(mode)
                                    tmask |= pmask;
                                else
                                    tmask ^= pmask;
                                sprintf(response, "$%d=%d", map->setting, (uint16_t)tmask);
                                status = sys_execute(response);
                            }
                        }
                    }
                    break;

                default:
                    break;
            }

            if(status != Status_OK)
                hal.stream.write("error:setting failure");
        }
    } else switch((webui_cmd_t)command) {

        case WebUICmd_GetCurrentIP:
            hal.stream.write(strappend(response, 3, args, "10.0.0.7", "\n"));
//            hal.stream.write(strappend(response, 3, args, wifi_get_ipaddr(), "\n"));
            break;

        case WebUICmd_GetSDCardStatus:
            hal.stream.write(hal.stream.type == StreamType_SDCard ? "Busy\n" : "SD card detected\n");
            break;

        case WebUICmd_GetSDCardContent:
                status = sys_execute("$F");
            break;

        case WebUICmd_PrintSD:
            status = Status_IdleError;
            if(hal.stream.type != StreamType_SDCard) { // Already streaming a file?
                char *cmd = get_arg(args, NULL, false);
                if(strlen(cmd) > 0) {
                    strcpy(response, "$F=");
                    strcat(response, cmd);
                    status = sys_execute(response);
                }
            }
            hal.stream.write(status == Status_OK ? "ok" : "error:cannot stream file");
            break;

        case WebUICmd_GetSettings:
            get_settings();
            break;

        case WebUICmd_SetEEPROMSetting:
            set_setting(args);
            break;

#if WIFI_ENABLE
        case WebUICmd_GetAPList:
            if(!get_ap_list())
                hal.stream.write("error");
            break;
#endif

        case WebUICmd_GetStatus:
            get_system_status();
            break;

        case WebUICmd_Reboot:
            {
                char *cmd = get_arg(args, NULL, false);
                if(!strcmp(cmd, "RESTART") && hal.reboot) {
                    hal.stream.write_all("[MSG:Restart ongoing]\r\n");
                    hal.delay_ms(1000, hal.reboot); // do the restart after a 1s delay, to allow the response to be sent
                } else
                    status = Status_InvalidStatement;
                hal.stream.write(status == Status_OK ? "ok" : "Error:Incorrect Command");
            }
            break;

#if FLASHFS_ENABLE
        case WebUICmd_ReadLocalFile:
            status = Status_IdleError;
            if(hal.stream.type != StreamType_FlashFs) { // Already streaming a file?
                char *cmd = get_arg(args, NULL, false);
                if(strlen(cmd) > 0) {
                    strcpy(response, "/spiffs");
                    strcat(response, cmd);
                    status = report_status_message(flashfs_stream_file(response));
                }
            }
            hal.stream.write(status == Status_OK ? "ok" : "error:cannot stream file");
            break;

        case WebUICmd_FormatFlashFS:
            {
                char *cmd = get_arg(args, NULL, false);
                status = Status_InvalidStatement;
                if(!strcmp(cmd, "FORMAT") && esp_spiffs_mounted(NULL)) {
                    hal.stream.write("Formating"); // sic
                    if(esp_spiffs_format(NULL) == ESP_OK)
                        status = Status_OK;
                }
                hal.stream.write(status == Status_OK ? "...Done\n" : "error\n");
            }
            break;

        case WebUICmd_GetFlashFSCapacity:
            {
                size_t total = 0, used = 0;
                if(esp_spiffs_info(NULL, &total, &used) == ESP_OK) {
                    strcpy(response, "SPIFFS  Total:");
                    strcat(response, btoa(total));
                    strcat(response, " Used:");
                    strcat(response, btoa(used));
                    hal.stream.write(strcat(response, "\n"));
                } else
                    status = Status_InvalidStatement;
            }
            break;
#endif

        case WebUICmd_GetFirmwareSpec:
            get_firmware_spec();
            break;

        default:
            status = Status_GcodeUnsupportedCommand;
            break;
    }

    get_arg(NULL, NULL, false); // free any memory allocated for argument parser

    return status;
}

webui_auth_level_t get_auth_required (uint32_t command, char *args)
{
    webui_auth_level_t level = WebUIAuth_None;

    switch(command) {

        case WebUICmd_GetSetSTA_SSID:
        case WebUICmd_GetSetSTA_IPMode:
        case WebUICmd_GetSetSTA_IP:
        case WebUICmd_GetSetAP_SSID:
        case WebUICmd_GetSetAP_IP:
        case WebUICmd_GetSetAP_Channel:
        case WebUICmd_GetSetRadioMode:
        case WebUICmd_GetSetHostname:
        case WebUICmd_GetSetHTTPOnOff:
        case WebUICmd_GetSetHttpPort:
        case WebUICmd_GetSetTelnetOnOff:
        case WebUICmd_GetSetTelnetPort:
        case WebUICmd_GetSetBluetoothName:
            level = *args ? WebUIAuth_Guest : WebUIAuth_Admin;
            break;

        case WebUICmd_GetSetSTA_Password:
        case WebUICmd_GetSetAP_Password:
        case WebUICmd_SetEEPROMSetting:
        case WebUICmd_Reboot:
        case WebUICmd_FormatFlashFS:
            level = WebUIAuth_Admin;
            break;

        case WebUICmd_GetSDCardStatus:
        case WebUICmd_GetSDCardContent:
        case WebUICmd_PrintSD:
        case WebUICmd_GetSettings:
        case WebUICmd_GetAPList:
        case WebUICmd_GetStatus:
        case WebUICmd_ReadLocalFile:
        case WebUICmd_GetFlashFSCapacity:
            level = WebUIAuth_User;
            break;

        default:
            break;
    }

    return level;
}

#endif
