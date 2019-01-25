#!/bin/bash

# Automated the entire process of switching the wireless interace between monitor and managed mode using airmon-ng, logging data to file and make the post request.
#
# To run the file script.sh
#
# ```sh
# $ chmod a+x ./script.sh
# $ sudo ./script.sh <YOUR_WIFI_INTERFACE> <SCAN_INTERVAL>
# ```
#
# e.g.
# 
# ```sh
# $ sudo ./script.sh wlp2s0 2s
# ```
#
# The second argument can be in seconds or minutes
# e.g.
#
# ```sh
# $ sudo ./script.sh wlp2s0 20s
# ```
#
# or
#
# ```sh
# $ sudo ./script.sh wlp2s0 2m
# ```
#
# If your network is not auto-connected then the curl request might fail.
# You can always connect to any network manually and make the following curl request.
#
# ```sh
# $ curl -i -X POST --data-binary "@data.log" http://ec2-13-233-63-78.ap-south-1.compute.amazonaws.com/putRecords
# ```


echo "Wireless interface at: $1"
sleep 1
echo "Will run scan for $2"
sleep 1
echo "Starting script"
sleep 1
echo "Running make..."
sleep 1
make
sleep 2
echo "Done!"
sleep 1
echo "Switching your wireless interface to monitor mode"
sleep 1
sudo airmon-ng start $1
sleep 1
MONITORINTERFACE=$1
MONITORINTERFACE+="mon"
SCANINTERVAL=$2
echo "Starting scan for probe requests. Log data will be sent after 2 mins"
sleep 2
sudo timeout $SCANINTERVAL ./probe_sniffer -i $MONITORINTERFACE | tee data.log
sleep $SCANINTERVAL
sleep 5s
echo "Switching wireless interface to managed mode. Wait till a network is connected"
sleep 3s
sudo airmon-ng stop $MONITORINTERFACE
sleep 10s
curl -i -X POST --data-binary "@data.log" http://ec2-13-233-63-78.ap-south-1.compute.amazonaws.com/putRecords
