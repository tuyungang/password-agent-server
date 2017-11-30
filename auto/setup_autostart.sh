#!/bin/sh -x
touch /etc/rc.local
chmod 777 /etc/rc.local
mkitab -i rcnfs "rc.local:2:once:/etc/rc.local> /dev/console 2>&1"
echo /home/hwcrm/tu/agent/c_agent_poll/startagent.sh > /etc/rc.local

