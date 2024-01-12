/*
  args.c - An embedded CNC Controller with rs274/ngc (g-code) support

  WebUI backend for https://github.com/luc-github/ESP3D-webui

  Part of grblHAL

  Copyright (c) 2022-2024 Terje Io

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

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "../grbl/nuts_bolts.h"

char *webui_get_arg (uint_fast16_t argc, char **argv, char *arg)
{
    char *value = NULL;
    size_t len = arg ? strlen(arg) : 0;

    if(arg == NULL)
        value = argc ? *argv : NULL;
    else if(argc && len) do {

        if(!strncmp(argv[--argc], arg, len))
            value = argv[argc] + len;

    } while(argc && value == NULL);

    return value;
}

bool webui_get_bool_arg (uint_fast16_t argc, char **argv, char *arg)
{
    char *value = webui_get_arg(argc, argv, arg);

    if(value)
        strcaps(value);
    else if(argc) {
        char tmp[16];
        memset(tmp, 0, sizeof(tmp));
        if(webui_get_arg(argc, argv, strncpy(tmp, arg, min(strlen(arg) - 1, sizeof(tmp) - 1))))
            return true;
    }

    return value != NULL && (!strcmp(value, "YES") || !strcmp(value, "TRUE") || !strcmp(value, "1"));
}

void webui_trim_arg (uint_fast16_t *argc, char **argv, char *arg)
{
    char *found = NULL;
    size_t len = strlen(arg);
    uint_fast16_t i = 0;

    if(*argc) do {
        if(!strncmp(argv[i], arg, len))
            found = argv[i];
        else
            i++;

    } while(i < *argc && found == NULL);

    if(found) {
        if(i < *argc) do {
             argv[i] = argv[i + 1];
             i++;
        } while(i < *argc);

        (*argc)--;
    }
}
