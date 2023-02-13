## WebUI plugin

Adds [ESP32-WEBUI](https://github.com/luc-github/ESP3D-webui) support for some networking capable boards and drivers.

This plugin sits on top of a heavily modified [lwIP](http://savannah.nongnu.org/projects/lwip/) raw mode http daemon.  

<sup>1</sup> FlashFS is erased when reflashing firmware!

#### Installation:

Enable WebUI support by uncommenting `#define WEBUI_ENABLE 1` in _my_machine.h_ and recompile/reflash.
This adds backends for both WebUI v2 and v3, set the define value to 2 or 3 to only add v2 or v3.

Ensure `$306` \(HTTP port\) is set to `80`, `$307` \(Websocket port\) is set to `81` and `$70` has flags set to enable both the http and websocket daemons. `15` is a safe value. Reboot.

For drivers with FlashFS support \(see table above\) enter `<ip address>/` or `<ip address>/?forcefallback=yes` as the browser URL,
the latter if it is for an update.  
Replace `<ip address>` with the controller IP address. Tip: Use `$I` to find the IP address if dynamically assigned. 
Then click on the _Interface_ top menu item in the page shown and navigate to the _dist/CNC/grblHAL_ folder and download _index.html.gz_.
You may download _index.html.gz_ directly via this [link](https://raw.githubusercontent.com/luc-github/ESP3D-WEBUI/3.0/dist/CNC/GRBLHal/index.html.gz).
Upload the file via the upload button in the _FileSystem_ panel.

For drivers without FlashFS support download directly or from [this page](https://github.com/luc-github/ESP3D-WEBUI/tree/3.0/dist/CNC/GRBLHal), create a _www_ folder on the SD card and copy the download file there.
If the SD card is mounted in the controller then the folder can be created and the file copied either via ftp or WebDAV provided the protocol to be used has been activated.

Finally enter the controller IP address in a browser window, if all is well the WebUI will then be loaded.

#### Alternative UI:

[grblTouch](https://github.com/karoria/grblTouch) by @karoria

---

#### Dependencies:

[Networking plugin](https://github.com/grblHAL/Plugin_networking)

[SD card plugin](https://github.com/grblHAL/Plugin_SD_card)

---
2023-02-13
