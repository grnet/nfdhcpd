#!/usr/bin/env python
from scapy.all import *
import argparse
import sys

def parse_options():
    parser = argparse.ArgumentParser()

    parser.add_argument("-n", dest="num",
                        default=None, type=int,
                        help="Packet number to show. Show all if not given.")

    parser.add_argument("pcapfile", type=str,
                        help="Pcap file generated with tcpdump -w")
 

    return parser.parse_args()

def main():
    opts = parse_options()
    try:
        paks = rdpcap(opts.pcapfile)
    except IOError:
        print "File does not exists"
        return 1
    except:
        print "Not a pcap file"
        return 1

    if opts.num is not None:
        try:
            p = paks[opts.num]
            p.show()
            return 0
        except IndexError:
            print "Packet number exceeds total packets captured (%d)!" % len(paks)
            return 1

    paks.show()
    return 0


if __name__ == "__main__":
    sys.exit(main())
