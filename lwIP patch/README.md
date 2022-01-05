### Patch for lwIP v2.0.x

#### iMXRT1062 \(Teensy 4.1\)

Copy [altcp.h](./altcp.h) to the _src\lwip_ subfolder of your _teensy41_ethernet-master_ library folder.

Replace _lwipopts.h_ in your _teensy41_ethernet-master_ library folder with the one from the [iMXRT1062](iMXRT1062) folder.  
Delete the _src/apps/httpd_ folder from your _teensy41_ethernet-master_ library folder.

#### MSP432E401Y

[altcp.h](./altcp.h) has been added to the driver sources so there is no need for any additional action.

---
2022-01-05
