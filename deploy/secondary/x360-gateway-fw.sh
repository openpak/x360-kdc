#!/bin/sh
# Idempotent: nft redirect of 360 SG initiations (3074 -> 13075) plus the INPUT accept for 13075 ahead of the first REJECT.
nft -f /etc/openpak/x360-gateway.nft
iptables -C INPUT -p udp --dport 13075 -j ACCEPT 2>/dev/null && exit 0
n=$(iptables -L INPUT -n --line-numbers | awk "/REJECT/{print \$1; exit}")
iptables -I INPUT "${n:-1}" -p udp --dport 13075 -j ACCEPT
