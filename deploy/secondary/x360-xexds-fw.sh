#!/bin/sh
# Idempotent: nft redirect of the 360 xexds probe (3074 -> 13074) plus the INPUT accept for 13074
# ahead of the first REJECT (rules appended after it never match; see the xb checklist notes).
nft -f /etc/openpak/x360-xexds.nft
iptables -C INPUT -p udp --dport 13074 -j ACCEPT 2>/dev/null && exit 0
n=$(iptables -L INPUT -n --line-numbers | awk "/REJECT/{print \$1; exit}")
iptables -I INPUT "${n:-1}" -p udp --dport 13074 -j ACCEPT
