#!/bin/bash

OUTPUT="${OUTPUT:-probe_requests.txt}"

if ! [ -x "$(command -v gawk)" ]; then
  echo 'gawk (GNU awk) is not installed. Please install gawk.' >&2
  exit 1
fi

if [ -z "$IFACE" ] ; then
	echo "IFACE env variable must be set. Type \"ifconfig\" to view network interaces."
	exit 1
fi

# filter with awk, then use sed to convert tabs to spaces and remove front and back quotes around SSID
# -i specifies the interface
# -e prints data-link headers
# -s captures upto s bytes per packet
# -I turns the interface in monitor mode
sudo tcpdump -l -I -i "$IFACE" -e -s 256 type mgt subtype probe-req | awk -f parse-tcpdump.awk | tee -a "$OUTPUT"
