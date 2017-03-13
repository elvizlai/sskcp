#!/bin/bash
rm -rf temp
rm -rf shadowsocks
git clone -b develop https://github.com/shadowsocks/shadowsocks-go.git temp
mv temp/shadowsocks shadowsocks
rm -rf temp
