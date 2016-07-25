#!/usr/bin/env python
# coding: utf-8

"""
查询前一百万域名的CNAME记录
"""

from sys import stdin

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import send
from scapy.all import IP, UDP, DNS, DNSQR

CNAME = 5


def get_sport_and_id(seed):
    high_bit, low_bit = divmod(seed, 2**16)
    return (high_bit << 12) + 1000, low_bit


count = 1

if __name__ == "__main__":
    for line in stdin:
        sport, dns_id = get_sport_and_id(seed=count)
        dns_query = IP(
            dst="8.8.8.8",
        )/UDP(
            sport=sport,
            dport=53,
        )/DNS(
            id=dns_id,
            rd=1,
            qd=DNSQR(
                qname=line.strip(),
                qtype=CNAME,
            ),
        )
        send([dns_query, dns_query, dns_query], verbose=0)
        count += 1
