#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IP_TMP=/tmp/ip.tmp
IP_BLACKLIST=/etc/ip-blacklist.conf
IP_BLACKLIST_TMP=/tmp/ip-blacklist.tmp
IP_BLACKLIST_CUSTOM=/etc/ip-blacklist-custom.conf # optional
list="chinese nigerian russian lacnic exploited-servers"
BLACKLISTS=(
"http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1" # Project Honey Pot Directory of Dictionary Attacker IPs
"http://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"  # TOR Exit Nodes
"http://www.maxmind.com/en/anonymous_proxies" # MaxMind GeoIP Anonymous Proxies
"http://danger.rulez.sk/projects/bruteforceblocker/blist.php" # BruteForceBlocker IP List
"http://rules.emergingthreats.net/blockrules/rbn-ips.txt" # Emerging Threats - Russian Business Networks List
"http://www.spamhaus.org/drop/drop.lasso" # Spamhaus Don't Route Or Peer List (DROP)
"http://cinsscore.com/list/ci-badguys.txt" # C.I. Army Malicious IP List
"http://www.openbl.org/lists/base.txt"  # OpenBL.org 30 day List
"http://www.autoshun.org/files/shunlist.csv" # Autoshun Shun List
"http://lists.blocklist.de/lists/all.txt" # blocklist.de attackers
)
for i in "${BLACKLISTS[@]}"
do
    curl "$i" > $IP_TMP
    grep -Po '(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?' $IP_TMP >> $IP_BLACKLIST_TMP
done
for i in `echo $list`; do
        # Download
        wget --quiet http://www.wizcrafts.net/$i-iptables-blocklist.html
        # Grep out all but ip blocks
        cat $i-iptables-blocklist.html | grep -v \< | grep -v \: | grep -v \; | grep -v \# | grep [0-9] > $i.txt
        # Consolidate blocks into master list
        cat $i.txt >> $IP_BLACKLIST_TMP
done

sort $IP_BLACKLIST_TMP -n | uniq > $IP_BLACKLIST
rm $IP_BLACKLIST_TMP
wc -l $IP_BLACKLIST
ipset create blacklist hash:net -exist
ipset flush blacklist
egrep -v "^#|^$" $IP_BLACKLIST | while IFS= read -r ip
do
        ipset add blacklist $ip
done

iptables -nL INPUT | grep "blacklist src" &>/dev/null  
if [[ $? -ne 0 ]]; then  
  iptables -I INPUT -m set --match-set blacklist src -j DROP
fi  
