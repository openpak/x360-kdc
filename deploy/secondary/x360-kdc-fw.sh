#!/bin/sh
# Idempotent: nft redirect UDP 88 -> 10088 plus the INPUT accept for 10088 ahead of the first REJECT.
nft -f /etc/openpak/x360-kdc.nft
iptables -C INPUT -p udp --dport 10088 -j ACCEPT 2>/dev/null && exit 0
n=$(iptables -L INPUT -n --line-numbers | awk "/REJECT/{print \$1; exit}")
iptables -I INPUT "${n:-1}" -p udp --dport 10088 -j ACCEPT
