#!/usr/bin/env python
# coding: utf-8

from sys import stdout

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import sniff
from scapy.all import send
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR

CNAME = 5


def extract_count_and_order(ip_id, dns_id):
    return ip_id >> 12 << 16 + dns_id, ip_id % 2 ** 12


def get_sport_and_id(count, order):
    high_bit, low_bit = divmod(count, 2 << 16)
    return high_bit << 12 + order, low_bit


def store(pkg):
    if pkg.haslayer(DNS) and pkg.haslayer(DNSRR) and pkg[DNS].ancount:
        # 是DNS 是DNS回答 有CNAME回答内容
        count, order = extract_count_and_order(pkg[IP].id, pkg[DNS].id)
        for i in range(pkg[DNS].ancount):
            if pkg[DNSRR][i].type == CNAME:
                record = "{count} {order} {address} {domain} {name}\n".format(
                    count=count,
                    order=order,
                    address=pkg[DNSRR][i].rdata,
                    domain=pkg[DNSQR].qname.rstrip("."),
                    name=pkg[DNSRR][i].rrname.rstrip("."),
                )
                stdout.write(record)
                ret_data = pkg[DNSRR][i].rdata

                sport, dns_id = get_sport_and_id(count, order+1)

                dns_query = IP(
                    dst="8.8.8.8",
                )/UDP(
                    sport=sport,
                    dport=53,
                )/DNS(
                    id=dns_id,
                    rd=1,
                    qd=DNSQR(
                        qname=ret_data.strip().rstrip("."),
                        qtype=CNAME,
                    ),
                )
                send([dns_query, dns_query, dns_query], verbose=0)

if __name__ == "__main__":
    filter_string = "src host 8.8.8.8 and udp src port 53"
    sniff(store=0, filter=filter_string, prn=store)
