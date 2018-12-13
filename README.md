# Probe-requests-sniffer-for-unix

A simple script to sniff for nearby probe-requests and log their:
  - SSID
  - MAC
  - Strength
  - Distance

### Pre-requisites
A wifi adapter with monitor mode and airmon-ng package installed.

### Usage
Git clone this repository and cd into the directory.

First find out your wifi interface with ifconfig.
```sh
$ ifconfig
```
will be something like
```sh
wlp2s0: ...
        ...
```

then
```sh
$ sudo airmon-ng start <YOUR_WIFI_INTERFACE>
```
This will start a new interface in monitor mode with "mon" appended to its name at the end. e.g. if your wifi interface was wlp2s0 then the new interface in monitor mode will be wlp2s0mon.

then set the interface name in your env and run the script. Don't forget to chmod first.
```sh
$ export IFACE=wlp2s0mon
$ chmod a+x ./sniff-probes.sh
$ ./sniff-probes.sh
```
