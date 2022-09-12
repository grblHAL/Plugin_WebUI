## WebUI plugin

Adds [ESP32-WEBUI](https://github.com/luc-github/ESP3D-webui) support for some networking capable boards and drivers.

Under development and partially implemented.  

This plugin sits on top of a heavily modified [lwIP](http://savannah.nongnu.org/projects/lwip/) raw mode http daemon.  
It requires lwIP version 2.1.0 or later, however 2.0.x can be patched to make it work.

The following drivers can be used with this plugin:

| Driver                                                            |lwIP version|patch required| FlashFS  |
|-------------------------------------------------------------------|------------|--------------|----------|
| [iMXRT1062 \(Teensy 4.1\)](https://github.com/grblHAL/iMXRT1062)  | 2.0.2      | yes          | littlefs |
| [RP2040 \(Pi Pico W\)](https://github.com/grblHAL/RP2040)         | 2.1.1      | no           | littlefs |
| [ESP32](https://github.com/grblHAL/ESP32)                         | ?          | no           | littlefs |
| [STM32F756](https://github.com/grblHAL/STM32F7xx)                 | 2.1.2      | no           | no       |
| [STM32H7xx](https://github.com/dresco/STM32H7xx)                  | ?          | no           | TBA      |
| [MSP432E401Y](https://github.com/grblHAL/MSP432E401Y)             | 2.0.2      | yes          | no       |

#### Installation:

Enable WebUI support by uncommenting `#define WEBUI_ENABLE 1` in _my_machine.h_ and recompile/reflash.

Ensure `$360` \(HTTP port\) is set to `80`, `$307` \(Websocket port\) is set to `81` and `$70` has flags set to enable both the http and websocket daemons. `15` is a safe value. Reboot.

For drivers with FlashFS support \(see table above\) enter `<ip address>/` or `<ip address>/?forcefallback=yes` if it is for an update.  
Replace `<ip address>` with the controller IP address. Tip: Use `$I` to find the IP address if dynamically assigned. 
Then click on the _Interface_ top menu item in the page shown and navigate to the _dist/CNC/grblHAL_ folder and download _index.html.gz_.
You may download _index.html.gz_ directly via this [link](https://raw.githubusercontent.com/luc-github/ESP3D-WEBUI/3.0/dist/CNC/GRBLHal/index.html.gz).
Upload the file via the upload button in the _FileSystem_ panel.

For drivers without FlashFS support download directly or from [this page](https://github.com/luc-github/ESP3D-WEBUI/tree/3.0/dist/CNC/GRBLHal), create a _www_ folder on the SD card and copy the download file there.
If the SD card is mounted in the controller then the folder can be created and the file copied either via ftp or WebDAV provided the protocol to be used has been activated.

Finally enter the controller IP address in a browser window, if all is well the WebUI will then be loaded.

#### lwIP patch:

lwIP v 2.1.0 introduced an alternate TCP API for SSL support, the new API is used by the http daemon and it fails if not available even if SSL support is not required.  
Luckily the new API can be bypassed by mapping the new API to the original.  The 2.1.0 distribution has a file that does this, this needs to be copied to the lwIP source code folder.  
In addition several symbols that controls lwIP features has to added or modified.
I have added these to Eclipse based build configurations, but sadly the Arduino IDE does not allow that.  

See the patch [readme](https://github.com/grblHAL/Plugin_WebUI/tree/3bc2b569057495f66e891c88bd073bc71ace8b83/lwIP%20patch) for instructions for how to apply it.

#### Alternative UI:

[grblTouch](https://github.com/karoria/grblTouch) by @karoria

---

#### Dependencies:

[Networking plugin](https://github.com/grblHAL/Plugin_networking)

[SD card plugin](https://github.com/grblHAL/Plugin_SD_card)

---
2022-09-03
