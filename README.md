# nmap-zabbix

Monitor ports visibility from the Internet and view results in Zabbix.

### Usage

Add cron entry (e.g every 5 minutes)

`sudo flock -n /tmp/zabbix_nmap.lockfile python3 start.py`

---
##### Exit codes

**0** - exit without errors<br>
**1** - script is not running as root<br>
**2** - Bad input values<br>