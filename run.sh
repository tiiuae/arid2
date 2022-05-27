#!/bin/bash
#Compile and Execute Setup Phase
shopt -s extglob
g++ !(join|sign|verify|open).cpp ./sha1/*.cpp ./base58/*.cpp -o setup -l pbc -l gmp
./setup < param/a.param

#Compile and Execute Join Phase
shopt -s extglob
g++ !(setup|sign|verify|open).cpp ./sha1/*.cpp ./base58/*.cpp -o join -l pbc -l gmp
./join < param/a.param

#Compile and Execute Signature Phase (I included also MAVSDK support)
#In case the link with the telemetry library is not working, please create a symbolink link --> sudo ln -s /usr/lib/libmavsdk_telemetry.so.0.37.0 /usr/lib/libmavsdk_telemetry.so
shopt -s extglob
g++ -std=c++17 -L/usr/lib -I/usr/local/include/mavsdk !(setup|join|verify|open).cpp ./sha1/*.cpp ./base58/*.cpp -o sign -l pbc -l gmp -ltins -lmavsdk -lmavsdk_telemetry
./sign < param/a.param

#Compile and Execute Signature Verification Phase
shopt -s extglob
g++ !(setup|join|sign|open).cpp ./sha1/*.cpp ./base58/*.cpp -o verify -l pbc -l gmp -ltins
./verify < param/a.param

#Compile and Execute Opening Procedure Phase
shopt -s extglob
g++ !(setup|join|sign|verify).cpp ./sha1/*.cpp ./base58/*.cpp -o open -l pbc -l gmp -ltins
./open < param/a.param