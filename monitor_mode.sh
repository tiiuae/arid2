#!/bin/bash          
export WIFI_INT=wlan0
sudo ip link set $WIFI_INT down
sudo iw dev $WIFI_INT set type monitor
sudo ip link set $WIFI_INT up
sudo iw $WIFI_INT set txpower fixed 3000
sudo iwconfig $WIFI_INT channel 1
iwconfig
