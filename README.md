# Probe-requests-sniffer-for-unix

A simple script to sniff for nearby probe-requests and log their:
  - SSID
  - MAC
  - Strength
  - Distance

### [Update]
Removed the dependency on tcpdump and added .c file which uses pcap to sniff probe requests.

##Usage
Same as below till "airmon-ng start" to start the interface. Then make to build

```sh
$ make
```

Then to start

```sh
$ sudo ./probe_sniffer -i <YOUR_WIFI_INTERFACE_IN_MONITOR_MODE>
```
e.g.
```sh
$ sudo ./probe_sniffer -i wlp2s0mon
```


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
