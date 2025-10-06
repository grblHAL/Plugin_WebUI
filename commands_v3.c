/*
  commands_v3.c - An embedded CNC Controller with rs274/ngc (g-code) support

  WebUI backend for https://github.com/luc-github/ESP3D-webui

  Part of grblHAL

  Copyright (c) 2019-2025 Terje Io

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

#if WEBUI_ENABLE == 1 || WEBUI_ENABLE == 3

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#include "networking/networking.h"
#include "networking/utils.h"

#include "args.h"
#include "webui.h"
#include "fs_handlers.h"

#include "grbl/vfs.h"
#include "grbl/report.h"
#include "grbl/strutils.h"
#include "grbl/state_machine.h"
#include "grbl/motion_control.h"
#include "grbl/stream_json.h"

#include "sdcard/sdcard.h"
#include "sdcard/fs_stream.h"

#if WIFI_ENABLE
#include "wifi.h"
#endif

//#include "flashfs.h"

#define WEBUI_EOL "\n"
#define FIRMWARE_ID "80"
#define FIRMWARE_TARGET "grblHAL"
#define JSON_MAX_DEPTH 15

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
    status_code_t (*handler)(const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);
    webui_auth_required_t auth;
    const char *help;
    webui_setting_map_t setting;
} webui_cmd_binding_t;

typedef enum {
   ResponseHdrType_MSG = 0,
   ResponseHdrType_AddObject,
   ResponseHdrType_AddArray
} response_hdr_type_t;

//typedef status_code_t (*webui_command_handler_ptr)(const webui_cmd_binding_t *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);

static status_code_t list_commands (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file);

// Shared functions

static json_out_t *json_create_response_hdr (uint_fast16_t cmd, response_hdr_type_t type, bool status_ok, const char *msg, vfs_file_t *file)
{
    bool ok;
    json_out_t *jstream;

    if((ok = !!(jstream = json_start(file, JSON_MAX_DEPTH)))) {
        ok = ok & json_add_string(jstream, "cmd", uitoa((uint32_t)cmd));
        ok = ok & json_add_string(jstream, "status", status_ok ? "ok" : "error");
        if(msg)
            ok = ok & json_add_string(jstream, "data", msg);
        else if(type != ResponseHdrType_MSG)
            ok = ok & (type == ResponseHdrType_AddArray ? json_start_array(jstream, "data") : json_start_tagged_object(jstream, "data"));
        else
            ok = false;
    }

    if(!ok && jstream) {
        json_end(jstream);
        jstream = NULL;
    }

    return jstream;
}

// Add value to the JSON response array
static bool json_add_value (json_out_t *jstream, char *id, char *value)
{
    bool ok = true;

    if((ok = json_start_object(jstream)))
    {
        ok = json_add_string(jstream, "id", id);
        ok = ok & json_add_string(jstream, "value", value);
        ok = ok & json_end_object(jstream);
    }

    return ok;
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

static status_code_t esp_setting (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    bool ok;
    char response[100];
    json_out_t *jstream = NULL;
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

            if(json) {
                ok = !!(jstream = json_create_response_hdr(command->id, ResponseHdrType_MSG, !!setting, svalue, file));
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

            if(json)
                jstream = json_create_response_hdr(command->id, ResponseHdrType_MSG, status == Status_OK, status == Status_OK ? "ok" : "Set failed", file);
        }
    } else switch(command->id) {

        case 103: // GetSetSTA_IP:
            status = Status_OK;
            if(argc == 0) {
                if(json) {

                    if((ok = !!(jstream = json_create_response_hdr(command->id, ResponseHdrType_AddObject, true, NULL, file)))) {

                        const setting_detail_t *setting;

                        if((setting = setting_get_details(Setting_IpAddress, 0)))
                            ok = ok & json_add_string(jstream, "ip", setting_get_value(setting, 0));

                        if((setting = setting_get_details(Setting_Gateway, 0)))
                            ok = ok & json_add_string(jstream, "gw", setting_get_value(setting, 0));

                        if((setting = setting_get_details(Setting_NetMask, 0)))
                            ok = ok & json_add_string(jstream, "msk", setting_get_value(setting, 0));

                        json_end_object(jstream);
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
                    jstream = json_create_response_hdr(command->id, ResponseHdrType_MSG, status == Status_OK, status == Status_OK ? "ok" : "Set failed", file);
            }
            break;

        default:
            break;
    }

    if(json_end(jstream))
       data_is_json();

    if(status != Status_OK && !json)
        vfs_puts("error:setting failure", file);

    return status;
}

// ESP111
static status_code_t get_current_ip (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    char response[20];

    if(json) {
        if(json_end(json_create_response_hdr(command->id, ResponseHdrType_MSG, true, webui_get_server_info()->status.ip, file)))
           data_is_json();
    } else
        vfs_puts(strappend(response, 3, argv[0], webui_get_server_info()->status.ip, WEBUI_EOL), file);

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
                if((hal.rtc.get_datetime(&time)))
                    snprintf(buf, sizeof(buf), "%4d-%02d-%02dT%02d:%02d:%02d", time.tm_year + 1900, time.tm_mon + 1, time.tm_mday, time.tm_hour, time.tm_min, time.tm_sec);
                else
                    strcpy(buf, "Time not available");
            }

            if(!ok || *buf == '\0' || argc) {
                ok = false;
                strcpy(buf, "No parameter");
            }

            if(json) {
                if(json_end(json_create_response_hdr(command->id, ResponseHdrType_MSG, ok, buf, file)))
                    data_is_json();
            } else {
                vfs_puts(buf, file);
                vfs_puts(WEBUI_EOL, file);
            }

        } else {

            if(json) {

                json_out_t *jstream;

                if((ok = !!(jstream = json_create_response_hdr(command->id, ResponseHdrType_AddObject, true, NULL, file)))) {

                    ok = ok & json_add_string(jstream, "srv1", "");
                    ok = ok & json_add_string(jstream, "srv2", "");
                    ok = ok & json_add_string(jstream, "srv3", "");
                    ok = ok & json_add_string(jstream, "zone", "GMT");
                    ok = ok & json_add_string(jstream, "dst", "NO");
                    ok = ok & json_end_object(jstream);

                    if(json_end(jstream))
                        data_is_json();
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
        if(json) {
            if(json_end(json_create_response_hdr(command->id, ResponseHdrType_MSG, false, "N/A", file)))
                data_is_json();
        } else
            vfs_puts("N/A" ASCII_EOL, file);
    }

    return Status_OK;
}

// ESP200
static status_code_t get_sd_status (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
#if FS_ENABLE & FS_SDCARD
    char *msg;

    if(argc == 1) {

        bool refresh = !!webui_get_arg(argc, argv, "REFRESH"), release = !!webui_get_arg(argc, argv, "RELEASE");

        UNUSED(refresh);

        webui_trim_arg(&argc, argv, "REFRESH"); // Mount?
        webui_trim_arg(&argc, argv, "RELEASE"); // Unmount?

        msg = argc ? "Unknown parameter" : (release ? "SD card released" : "SD card ok");

    } else
        msg = hal.stream.type == StreamType_SDCard ? "Busy" : (sdcard_getfs() ? "SD card detected" : "Not available");
#else
    char *msg = "Not available";
#endif

    if(json) {
        if(json_end(json_create_response_hdr(command->id, ResponseHdrType_MSG, true, msg, file)))
            data_is_json();
    } else {
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

static void show_pin_json (xbar_t *pin, void *jstream)
{
    char id[10];

    strcat(strcpy(id, (char *)pin->port), uitoa(pin->pin));

    json_add_value((json_out_t *)jstream, (char *)get_pinname(pin->function), id);
}

static void show_pin_txt (xbar_t *pin, void *file)
{
    char buf[50];

    vfs_puts(strappend(buf, 5, (char *)pin->port, uitoa(pin->pin), ": ", get_pinname(pin->function), WEBUI_EOL), (vfs_file_t *)file);
}

static status_code_t show_pins (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    if(json) {

        json_out_t *jstream;

        if(hal.enumerate_pins && !!(jstream = json_create_response_hdr(command->id, ResponseHdrType_AddArray, true, NULL, file))) {
            hal.enumerate_pins(false, show_pin_json, jstream);
            if(json_end_array(jstream) && json_end(jstream))
               data_is_json();
        }
    } else
        hal.enumerate_pins(false, show_pin_txt, file);

    return Status_OK; // for now
}

// ESP400


// Add setting to the JSON response array
static bool add_setting (json_out_t *jstream, const setting_detail_t *setting, int32_t bit, uint_fast16_t offset)
{
    static const char *tmap[] = { "B", "M", "X", "B", "M", "I", "F", "S", "S", "A", "I", "I" };

    bool ok;

    if((ok = setting && (setting->is_available == NULL || setting->is_available(setting, offset)) && json_start_object(jstream))) {

        char opt[50], name[50], *q;
        uint_fast8_t suboffset = setting->flags.subgroups ? offset / setting->flags.increment : offset;
        const setting_group_detail_t *group = setting_get_group_details(setting->group + (setting->flags.subgroups ? suboffset : 0));

        if(setting->datatype == Format_Bool)
            bit = 0;

        if(setting->group == Group_Axis0) {
            strcpy(name, setting->name + 1);
            *name = CAPS(*name);
        } else if((q = strchr(setting->name, '?'))) {
            strncpy(name, setting->name, q - setting->name);
            name[q - setting->name] = '\0';
            strcat(name, uitoa(suboffset + 1));
            strcat(name, q + 1);
        } else
            strcpy(name, setting->name);

        strcpy(opt, group->name);
        strcat(opt, "/");
        strcat(opt, group->name);

        ok = json_add_string(jstream, "F", opt);

        strcpy(opt, uitoa(setting->id + offset));
        if(bit >= 0) {
            strcat(opt, "#");
            strcat(opt, uitoa(bit));
        }
        ok = ok & json_add_string(jstream, "P", opt);
        ok = ok & json_add_string(jstream, "T", tmap[setting->datatype]);
        ok = ok & json_add_string(jstream, "V", bit == -1 ? setting_get_value(setting, offset) : setting_get_int_value(setting, offset) & (1 << bit) ? "1" : "0");
        ok = ok & json_add_string(jstream, "H", bit == -1 || setting->datatype == Format_Bool ? name : strgetentry(opt, setting->format, bit, ','));
        if(setting->unit)
            ok = ok & json_add_string(jstream, "U", setting->unit);
        if(setting->flags.reboot_required)
            ok = ok & json_add_string(jstream, "R", "1");

        if(ok) switch(setting->datatype) {

            case Format_Bool:
            case Format_Bitfield:
            case Format_XBitfield:
            case Format_RadioButtons:
                {
                    if((ok = json_start_array(jstream, "O"))) {
                        if(bit == -1) {
                            uint_fast16_t i, j = strnumentries(setting->format, ',');
                            for(i = 0; ok && i < j; i++) {
                          //      option = cJSON_CreateObject();
                          //      if(isv3 && i == 0)
                          //          cJSON_AddStringToObject(option, strgetentry(opt, setting->format, i, ','), uitoa(1 << bit));
                          //      else
                                if(strcmp(strgetentry(opt, setting->format, i, ','), "N/A")) {
                                    if((ok = json_start_object(jstream))) {
                                        ok = json_add_string(jstream, opt, uitoa(i));
                                        json_end_object(jstream);
                                    }
                                }
                            }
                        } else if((ok = json_start_object(jstream))) {
                            ok = json_add_string(jstream, "Enabled", "1");
                            json_end_object(jstream);
                            if((ok = json_start_object(jstream))) {
                                ok = ok & json_add_string(jstream, "Disabled", "0");
                                json_end_object(jstream);
                            }
                        }
                        json_end_array(jstream);
                    }
                }
                break;

            case Format_AxisMask:
                {
                    uint_fast16_t i;

                    if((ok = json_start_array(jstream, "O"))) {
                        for(i = 0; ok && i < N_AXIS; i++) {
                            if((ok = json_start_object(jstream))) {
                                ok = ok & json_add_string(jstream, axis_letter[i], uitoa(i));
                                json_end_object(jstream);
                            }
                        }
                        json_end_array(jstream);
                    }
                }
                break;

            case Format_IPv4:
                break;

            default:
                {
                    char whole[30] = "", fraction[10] = "";
                    const char *min = setting->min_value, *max = setting->max_value;

                    if(setting->format && (setting->datatype == Format_Decimal || setting_is_integer(setting))) {

                        char c, *s1 = (char *)setting->format, *s2 = whole;

                        while((c = *s1++)) {
                            if(c == '.')
                                s2 = fraction;
                            else {
                                *s2++ = '9';
                                *s2 = '\0';
                            }
                        }

                        if(*fraction != '\0')
                            strcat(strcat(strcpy(opt, whole), "."), fraction);
                        else
                            strcpy(opt, whole);

                        if(min == NULL)
                            min = *setting->format == '-' ? strcat(strcpy(whole, "-"), opt) : "0";

                        if(max == NULL)
                            max = opt;

                        if(setting->datatype == Format_Decimal)
                            ok = ok & json_add_string(jstream, "E", uitoa(strlen(fraction)));
                    }

                    if(min && !setting_is_list(setting)) {
                        ok = ok & json_add_string(jstream, "M", setting->flags.allow_null ? "0" : min);
                        if(setting->flags.allow_null)
                            ok = ok & json_add_string(jstream, "MS", min);
                    }

                    if(max)
                        ok = ok & json_add_string(jstream, "S", max);
                }
                break;
        }

        ok = json_end_object(jstream);
    }

    return ok;
}

static bool add_setting2 (const setting_detail_t *setting, uint_fast16_t offset, void *jstream)
{
    return add_setting((json_out_t *)jstream, setting, -1, offset);
}

static int cmp_settings (const void *a, const void *b)
{
    uint32_t av = ((*(setting_detail_t **)(a))->group << 16) | (*(setting_detail_t **)(a))->id,
             bv = ((*(setting_detail_t **)(b))->group << 16) | (*(setting_detail_t **)(b))->id;

    return av - bv;
}

static status_code_t get_settings (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    bool ok;
    uint_fast16_t idx, n_settings = 0;
    json_out_t *jstream = json_start(file, JSON_MAX_DEPTH);
    setting_details_t *details = settings_get_details();
    const setting_detail_t *setting;
    setting_detail_t **all_settings, **psetting;

    if((ok = jstream != NULL)) {
        ok = ok & json_add_string(jstream, "cmd", uitoa(command->id));
        ok = ok & json_add_string(jstream, "status", "ok");
    }

    if((ok = ok & json_start_array(jstream, "data"))) {

        do {
            n_settings += details->n_settings;
        } while((details = details->next));

        details = settings_get_details();

        if((all_settings = psetting = calloc(n_settings, sizeof(setting_detail_t *)))) {

            n_settings = 0;

            do {
                for(idx = 0; idx < details->n_settings; idx++) {
                    setting = &details->settings[idx];
                    if(setting->is_available == NULL || setting->is_available(setting, 0)) {
                        *psetting++ = (setting_detail_t *)setting;
                        n_settings++;
                    }
                }
            } while((details = details->next));

            qsort(all_settings, n_settings, sizeof(setting_detail_t *), cmp_settings);

            for(idx = 0; ok && idx < n_settings; idx++)
                ok = settings_iterator(all_settings[idx], add_setting2, jstream);

            free(all_settings);

        } else do {
            for(idx = 0; ok && idx < details->n_settings; idx++) {
                setting = &details->settings[idx];
                if(setting->is_available == NULL || setting->is_available(setting, 0))
                    ok = settings_iterator(setting, add_setting2, jstream);
            }
        } while((details = details->next));
    }

    if(jstream) {
        if(ok) {
            json_end_array(jstream);
            data_is_json();
        }
        json_end(jstream);
    }

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
        setting_id_t id = (setting_id_t)atoi(setting_id);

        ok = !!(setting = setting_get_details(id, NULL));

        // "hack" for bitfield settings
        if(ok && (bitp = strchr(setting_id, '#'))) {

            *bitp++ = '\0';
            uint32_t pmask = 1 << atoi(bitp), tmask;

            tmask = setting_get_int_value(setting, 0);

            if(*value == '0')
                tmask ^= pmask;
            else
                tmask |= pmask;

            if(setting->datatype == Format_XBitfield && (tmask & 0x01) == 0)
                tmask = 0;

            value = uitoa(tmask);
        }

        if(ok) {

            // Block disable of websocket daemon from WebUI
            if(setting->id == Setting_NetworkServices) {
                network_services_t services;
                services.mask = (uint8_t)atoi(value);
                if(!services.websocket) {
                    services.websocket = On;
                    value = uitoa(services.mask);
                }
            }

            status = sys_set_setting(id, value);
        }
    }

    if(json) {

        const char *msg = errors_get_description(status);

        if(json_end(json_create_response_hdr(command->id, ResponseHdrType_MSG, status == Status_OK, status == Status_OK ? "ok" : (msg ? msg : "Set failed"), file)))
            data_is_json();
    } else
        grbl.report.status_message(status);

    return status;
}

#if WIFI_ENABLE

// ESP410
static status_code_t get_ap_list (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    bool ok = false;
    json_out_t *jstream;

    wifi_ap_scan();

    ap_list_t *ap_list = wifi_get_aplist();

    if((ok = !!(jstream = json_create_response_hdr(command->id, ResponseHdrType_AddArray, true, NULL, file)))) {

        if(ap_list && ap_list->ap_records) {

            for(int i = 0; i < ap_list->ap_num; i++) {
                if((ok = json_start_object(jstream)))
                {
                    ok = json_add_string(jstream, "SSID", (char *)ap_list->ap_records[i].ssid);
                    ok = ok & json_add_int(jstream, "SIGNAL", (int32_t)ap_list->ap_records[i].rssi);
                    ok = ok & json_add_string(jstream, "IS_PROTECTED", ap_list->ap_records[i].authmode == WIFI_AUTH_OPEN ? "0" : "1");
                    ok = ok & json_end_object(jstream);
                }
            }
        }

        ok = ok & json_end_array(jstream);
    }

    if(json_end(jstream))
       data_is_json();

    if(ap_list)
        wifi_release_aplist();

    return Status_OK; // for now
}

#endif

// ESP420

status_code_t webui_v3_get_system_status (uint_fast16_t command_id, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    char buf[200];
    vfs_free_t *mount;
    vfs_drive_t *sdfs = fs_get_sd_drive(); //, *flashfs = fs_get_flash_drive();
    network_info_t *network = webui_get_server_info();

    mount = sdfs ? vfs_drive_getfree(sdfs) : NULL;

    if(json) {

        bool ok;
        json_out_t *jstream;

        if((ok = !!(jstream = json_create_response_hdr(command_id, ResponseHdrType_AddArray, true, NULL, file)))) {

            if(hal.get_free_mem)
                ok = ok & json_add_value(jstream, "free mem", btoa(hal.get_free_mem()));

//            ok = ok & json_add_value(data, "chip id", "0");
            ok = ok & json_add_value(jstream, "CPU Freq", strcat(strcpy(buf, uitoa(hal.f_mcu ? hal.f_mcu : hal.f_step_timer / 1000000UL)), " MHz"));

            if(mount) {

                ok = ok & json_add_value(jstream, "FS type", "SD");

                strcpy(buf, btoa(mount->size));
                strcat(buf, "/");
                strcat(buf, btoa(mount->used));
                ok = ok & json_add_value(jstream, "FS usage", buf);
            }

#if WIFI_ENABLE
            ok = ok & json_add_value(jstream, "wifi", "ON");
#elif ETHERNET_ENABLE
            ok = ok & json_add_value(jstream, "wifi", "OFF");
            ok = ok & json_add_value(jstream, "ethernet", "ON");
#endif
            if(network->status.services.http)
                ok = ok & json_add_value(jstream, "HTTP port", uitoa(network->status.http_port));
            if(network->status.services.telnet)
                ok = ok & json_add_value(jstream, "Telnet port", uitoa(network->status.telnet_port));
            if(network->status.services.webdav)
                ok = ok & json_add_value(jstream, "WebDav port", uitoa(network->status.http_port));
            if(network->status.services.ftp) {
                strappend(buf, 3, uitoa(network->status.ftp_port), "/", uitoa(network->status.ftp_port));
                ok = ok & json_add_value(jstream, "Ftp ports", buf);
            }
            if(network->status.services.websocket)
                ok = ok & json_add_value(jstream, "Websocket port", uitoa(network->status.websocket_port));

            if(network->is_ethernet) {

                if(*network->mac != '\0')
                    ok = ok & json_add_value(jstream, "ethernet", network->mac);

                if(network->link_up)
                    strappend(buf, 3, "connected (", uitoa(network->mbps), "Mbps)");
                else
                    strcpy(buf, "disconnected");
                ok = ok & json_add_value(jstream, "cable", buf);

                ok = ok & json_add_value(jstream, "ip mode", network->status.ip_mode == IpMode_Static ? "static" : "dhcp");
                ok = ok & json_add_value(jstream, "ip", network->status.ip);

                if(*network->status.gateway != '\0')
                    ok = ok & json_add_value(jstream, "gw", network->status.gateway);

                if(*network->status.mask != '\0')
                    ok = ok & json_add_value(jstream, "msk", network->status.mask);

                if(network->status.services.dns)
                    ok = ok & json_add_value(jstream, "DNS", network->status.gateway);
            }

#if WEBUI_AUTH_ENABLE
            ok = ok & json_add_value(jstream, "authentication", "ON");
#endif
//            ok = ok & json_add_value(data, "flash", "OFF");
            if(sdfs)
                strappend(buf, 3, "direct (", sdfs->name, ")");
            else
                strcpy(buf, "none");
            ok = ok & json_add_value(jstream, "sd", buf);

            ok = ok & json_add_value(jstream, "targetfw", FIRMWARE_TARGET);
            strappend(buf, 3, GRBL_VERSION, "-", uitoa(GRBL_BUILD));
            ok = ok & json_add_value(jstream, "FW ver", buf);
            ok = ok & json_add_value(jstream, "FW arch", hal.info);
            ok = ok & json_end_array(jstream);

            if(json_end(jstream))
               data_is_json();
        }
    } else {

        if(hal.get_free_mem)
            vfs_puts(strappend(buf, 3, "free mem: ", btoa(hal.get_free_mem()), WEBUI_EOL), file);

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
            vfs_puts(strappend(buf, 3, "sd direct (", sdfs->name, ")" WEBUI_EOL), file);
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

// Shared functions for ESP7xx

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
    json_out_t *jstream = NULL;

    if(drive) {

        char *arg = webui_get_arg(argc, argv, NULL);

        if(json) {
            if((ok = !!(jstream = json_create_response_hdr(command->id, ResponseHdrType_AddObject, true, NULL, file)))) {
                ok = ok & json_add_string(jstream, "path", get_path(path, arg ? arg : "/", drive));
                ok = ok & fs_ls(jstream, path, NULL, drive);
                ok = ok & json_end_object(jstream);
            }
        }
    } else
        jstream = json_create_response_hdr(command->id, ResponseHdrType_MSG, false, "Not mounted", file);

    if(json_end(jstream))
       data_is_json();

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

    if(json) {
        if(json_end(json_create_response_hdr(command->id, ResponseHdrType_MSG, ok, response, file)))
            data_is_json();
    } else
        vfs_puts(response, file);

    return Status_OK; // for now
}

// ESP700
static status_code_t flash_read_file (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    bool ok = false;
    char *cmd = webui_get_arg(argc, argv, NULL), msg[50];
    vfs_drive_t *drive = fs_get_flash_drive(true);

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

    if(json) {
        if(json_end(json_create_response_hdr(command->id, ResponseHdrType_MSG, ok, msg, file)))
            data_is_json();
    } else
        vfs_puts(strcat(msg, WEBUI_EOL), file);

    return Status_OK;
}

// ESP701
static status_code_t handle_job_status (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    bool ok;
    stream_job_t *job = stream_get_job_info();
    json_out_t *jstream;
    char *action = webui_get_arg(argc, argv, "action=");

    if((ok = !!(jstream = json_create_response_hdr(command->id, ResponseHdrType_AddObject, true, NULL, file)))) {

        if(action) {

            switch(strlookup(action, "PAUSE,RESUME,ABORT", ',')) {

                case 0:
                    if(job)
                        grbl.enqueue_realtime_command(CMD_FEED_HOLD);
                    ok = ok & json_add_string(jstream, "status", job ? "Stream paused" : "No stream to pause");
                    break;

                case 1:
                    if(job)
                        grbl.enqueue_realtime_command(CMD_CYCLE_START);
                    ok = ok & json_add_string(jstream, "status", job ? "Stream resumed" : "No stream to resume");
                    break;

                case 2:
                    if(job)
                        grbl.enqueue_realtime_command(CMD_STOP);
                    ok = ok & json_add_string(jstream, "status", job ? "Stream aborted" : "No stream to abort");
                    break;

                default:
                    ok = ok & json_add_string(jstream, "status", "Unknown action");
                    break;
            }

        } else if(job) {

            switch(state_get()) {

                case STATE_HOLD:
                    ok = ok & json_add_string(jstream, "status", "pause stream");
                    break;

                default:
                    ok = ok & json_add_string(jstream, "status", "processing");
                    ok = ok & json_add_string(jstream, "total", uitoa(job->size));
                    ok = ok & json_add_string(jstream, "processed", uitoa(job->pos));
                    ok = ok & json_add_string(jstream, "type", "SD");
                    ok = ok & json_add_string(jstream, "name", job->name);
                    break;
            }

        } else {

            ok = ok & json_add_string(jstream, "status", "no stream");
            if(gc_state.last_error != Status_OK)
                ok = ok & json_add_string(jstream, "code", uitoa(gc_state.last_error));
        }

        json_end_object(jstream);
    }

    if(json_end(jstream))
       data_is_json();

    return Status_OK;
}

// ESP710
static status_code_t flash_format (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    bool ok;
    char *cmd = webui_get_arg(argc, argv, NULL);

    vfs_drive_t *drive = fs_get_flash_drive(true);

    if((ok = !strcmp(cmd, "FORMATFS") && drive)) {
        if(!json)
            vfs_puts("Start Formating" WEBUI_EOL, file); // sic
        ok = vfs_drive_format(drive) == 0;
    }

    if(json) {
        if(json_end(json_create_response_hdr(command->id, ResponseHdrType_MSG, ok, ok ? "ok" : "Invalid parameter", file)))
            data_is_json();
    } else
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

    if(json) {
        if(json_end(json_create_response_hdr(command->id, ResponseHdrType_MSG, ok, ok ? "ok" : "Invalid parameter", file)))
            data_is_json();
    } else
        vfs_puts(ok ? "ok" WEBUI_EOL : "Invalid parameter" WEBUI_EOL, file);

    return Status_OK;
}

// ESP720
static status_code_t flashfs_ls (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    return fs_list_files(command, argc, argv, json, file, fs_get_flash_drive(true));
}

// ESP730
static status_code_t flashfs_action (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    return fs_action(command, argc, argv, json, file, fs_get_flash_drive(true));
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

// ESP800
static status_code_t get_firmware_spec (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    uint_fast16_t idx;
    char buf[200], hostpath[16], axisletters[10];
    network_info_t *network = webui_get_server_info();
    vfs_drive_t *sdfs = fs_get_sd_drive(), *flashfs = fs_get_flash_drive(webui_maintenance_mode());

    strcpy(hostpath, webui_get_sys_path());
    if(*hostpath == '\0')
        strcpy(hostpath, sdfs && flashfs == NULL ? "/www" : "/");
    vfs_fixpath(hostpath);

    for(idx = 0; idx < N_AXIS; idx++)
        axisletters[idx] = *axis_letter[idx];

    axisletters[idx] = '\0';

    if(json) {

        bool ok;
        json_out_t *jstream;

        if((ok = !!(jstream = json_create_response_hdr(command->id, ResponseHdrType_AddObject, true, NULL, file)))) {

            ok = ok & json_add_string(jstream, "FWVersion", GRBL_VERSION);
            ok = ok & json_add_string(jstream, "FWTarget", FIRMWARE_TARGET);
            ok = ok & json_add_string(jstream, "FWTargetID", FIRMWARE_ID);
            ok = ok & json_add_string(jstream, "Setup", "Enabled");
            ok = ok & json_add_string(jstream, "SDConnection", sdfs ? "direct" : "none");
            ok = ok & json_add_string(jstream, "SerialProtocol", "Socket");
#if WEBUI_AUTH_ENABLE
            ok = ok & json_add_string(jstream, "Authentication", "Enabled");
#else
            ok = ok & json_add_string(jstream, "Authentication", "Disabled");
#endif
            ok = ok & json_add_string(jstream, "WebCommunication", "Synchronous");
            ok = ok & json_add_string(jstream, "WebSocketIP", network->status.ip);
            ok = ok & json_add_string(jstream, "WebSocketSubProtocol", "webui-v3");
            ok = ok & json_add_string(jstream, "WebSocketPort", uitoa(network->status.websocket_port));
            ok = ok & json_add_string(jstream, "Hostname", network->status.hostname);
#if WIFI_ENABLE
  #if WIFI_SOFTAP
            ok = ok & json_add_string(jstream, "WiFiMode", "AP");
  #else
            ok = ok & json_add_string(jstream, "WiFiMode", "STA");
  #endif
#endif
            ok = ok & json_add_string(jstream, "FlashFileSystem", flashfs ? flashfs->name : "none");
            ok = ok & json_add_string(jstream, "HostPath", hostpath);
            ok = ok & json_add_string(jstream, "WebUpdate", /*flashfs || sdfs ? "Enabled" :*/ "Disabled");
            ok = ok & json_add_string(jstream, "FileSystem", flashfs ? "flash" : "none");

            if(hal.rtc.get_datetime) {
                struct tm time;
                ok = ok & json_add_string(jstream, "Time", hal.rtc.get_datetime(&time) ? "Manual" : "Not set");
            } else
                ok = ok & json_add_string(jstream, "Time", "none");

            ok = ok & json_add_string(jstream, "Axisletters", axisletters);
            ok = ok & json_end_object(jstream);

            if(json_end(jstream))
               data_is_json();
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

        vfs_puts(strappend(buf, 3, "Axisletters:", axisletters, WEBUI_EOL), file);
    }

    return Status_OK;
}

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
    { 720, flashfs_ls,         { WebUIAuth_Guest, WebUIAuth_Admin}, "<jstream> json=<no> pwd=<admin password> - list flash file system" },
    { 730, flashfs_action,     { WebUIAuth_Guest, WebUIAuth_Admin}, "<create|exists|remove|mkdir|rmdir>=<path> (json=no) - action on flash file system" },
    { 740, sdcard_ls,          { WebUIAuth_Guest, WebUIAuth_Admin}, "<jstream> json=<no> pwd=<admin password> - list sd file system" },
    { 750, sdcard_action,      { WebUIAuth_Guest, WebUIAuth_Admin}, "<create|exists|remove|mkdir|rmdir>=<path> (json=no) - action on sd file system" },
    { 780, global_fs_ls,       { WebUIAuth_Guest, WebUIAuth_Admin}, "<jstream> json=<no> pwd=<admin password> - list global file system" },
    { 790, global_fs_action,   { WebUIAuth_Guest, WebUIAuth_Admin}, "<create|exists|remove|mkdir|rmdir>=<path> (json=no) - action on global file system" },
    { 800, get_firmware_spec,  { WebUIAuth_Guest, WebUIAuth_Guest}, "(json=yes) - display FW Informations in plain/JSON" }
};

// ESP0
static status_code_t list_commands (const struct webui_cmd_binding *command, uint_fast16_t argc, char **argv, bool json, vfs_file_t *file)
{
    bool ok;
    char buf[200];
    int32_t cmd = -1;
    const webui_cmd_binding_t *cmdp = NULL;
    uint32_t i, n = sizeof(webui_commands) / sizeof(webui_cmd_binding_t);
    json_out_t *jstream = NULL;

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
            if((ok = !!(jstream = json_create_response_hdr(command->id, ResponseHdrType_AddObject, cmdp != NULL, cmdp == NULL ? buf : NULL, file)))) {
                if(cmdp) {
                    ok = ok & json_add_string(jstream, "id", uitoa(cmdp->id));
                    ok = ok & json_add_string(jstream, "help", buf);
                }
            }

            json_end_object(jstream);

        } else {
            vfs_puts(buf, file);
            vfs_puts(WEBUI_EOL, file);
        }
    } else if(json) {

        if((ok = !!(jstream = json_create_response_hdr(command->id, ResponseHdrType_AddArray, true, NULL, file)))) {

            for(i = 0; i < n; i++) {
                if((ok = json_start_object(jstream)))
                {
                    sprintf(buf, "[ESP%d]%s", webui_commands[i].id, webui_commands[i].help);

                    ok = ok & json_add_string(jstream, "id", uitoa(webui_commands[i].id));
                    ok = ok & json_add_string(jstream, "help", buf);
                    ok = ok & json_end_object(jstream);
                }
            }

            json_end_array(jstream);
        }
    } else {
        vfs_puts("[List of ESP3D commands]" WEBUI_EOL, file);
        for(i = 0; i < n; i++) {
            sprintf(buf, "[ESP%d]%s" WEBUI_EOL, webui_commands[i].id, webui_commands[i].help);
            vfs_puts(buf, file);
        }
    }

    if(json_end(jstream))
        data_is_json();

    return Status_OK;
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
                if(json) {
                    if(json_end(json_create_response_hdr(webui_commands[i].id, ResponseHdrType_MSG, true, "Wrong authentication level", file)))
                        data_is_json();
                } else
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

#endif // WEBUI_ENABLE
