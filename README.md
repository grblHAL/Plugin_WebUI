## WebUI plugin

Adds [ESP32-WEBUI](https://github.com/luc-github/ESP3D-webui) support for some networking capable boards and drivers.

Under development and partially implemented. Support for authentication is not yet ready and there is no support for a flash based file system \(and I do not plan to add that\).

This plugin sits on top of a heavily modified [lwIP](http://savannah.nongnu.org/projects/lwip/) raw mode http daemon.  
It requires lwIP version 2.1.0 or later, however 2.0.x can be patched to make it work.

The following drivers can be used with this plugin:

| Driver                                                            |lwIP version|patch required|
|-------------------------------------------------------------------|------------|--------------|
| [STM32F756](https://github.com/grblHAL/STM32F7xx)                 | 2.1.2      | no           |
| [iMXRT1062 \(Teensy 4.1\)](https://github.com/grblHAL/iMXRT1062)  | 2.0.2      | yes          |
| [MSP432E401Y](https://github.com/grblHAL/MSP432E401Y)             | 2.0.2      | yes          |

#### Installation:

Copy the provided [www](./www) folder to the root of the SD card.

Enable WebUI support by uncommenting `WEBUI_ENABLE` in _my_machine.h_ and recompile/reflash.

Ensure `$360` \(HTTP port\) is set to `80`, `$307` \(Websocket port\) is set to `81` and `$70` has flags set to enable both the http and websocket daemons. `15` is a safe value. Reboot.

Enter the controller IP address in a browser window, if all is well the WebUI will then be loaded. Tip: Use `$I` to find the IP address if dynamically assigned.

#### lwIP patch:

lwIP v 2.1.0 introduced an alternate TCP API for SSL support, the new API is used by the http daemon and it fails if not available even if SSL support is not required.  
Luckily the new API can be bypassed by mapping the new API to the original.  The 2.1.0 distribution has a file that does this, this needs to be copied to the lwIP source code folder.  
In addition several symbols that controls lwIP features has to added or modified.
I have added these to Eclipse based build configurations, but sadly the Arduino IDE does not allow that.  

See the patch [readme](https://github.com/grblHAL/Plugin_WebUI/tree/3bc2b569057495f66e891c88bd073bc71ace8b83/lwIP%20patch) for instructions for how to apply it.

---

__Note:__ The [ESP32 driver](https://github.com/grblHAL/ESP32) has its own WebUI implementation on top of the Espressif socket based http daemon and thus does not use this plugin.

#### Dependencies:

[Networking plugin](https://github.com/grblHAL/Plugin_networking)

[SD card plugin](https://github.com/grblHAL/Plugin_SD_card)

---
2021-09-18
