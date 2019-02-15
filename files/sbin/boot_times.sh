#!/bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
BOOT_TIMES=/etc/config/boot_times


#升级启动次数
if [ ! -f $BOOT_TIMES ] ;then
        echo "boot_times=1" > $BOOT_TIMES
else
        . $BOOT_TIMES
        boot_times=`expr  $boot_times + 1`
        echo "boot_times=$boot_times" > $BOOT_TIMES
fi

#系统内存优化
echo 3 > /proc/sys/vm/drop_caches

if [ -f /usr/sbin/telnetd ] ;then
	/etc/init.d/telnet stop
	sleep 1
	telnetd & 
fi
