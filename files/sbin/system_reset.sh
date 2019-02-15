#!/bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

if [ -f /sbin/modify_mac ]; then
	/sbin/modify_mac
fi
sync
sleep 1
mtd -r erase rootfs_data 
