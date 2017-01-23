# Copyright (c) 2010-2017 GRNET SA
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

import os
import logging
import socket
import IPy

from scapy.data import ETH_P_ALL
from scapy.packet import BasePacket

class Subnet(object):
    def __init__(self, net=None, gw=None, dev=None):
        if isinstance(net, str):
            try:
                self.net = IPy.IP(net)
            except ValueError, e:
                logging.warning(" - IPy error: %s", e)
                raise e
        else:
            self.net = net
        self.gw = gw
        self.dev = dev

    def __getitem__(self, idx):
        """ Return the n-th address (network+idx) in the subnet (self.net)

        """
        if self.net and isinstance(self.net, IPy.IP):
            return self.net[idx]
        else:
            return None

    @property
    def netmask(self):
        """ Return the netmask in textual representation

        """
        return str(self.net.netmask())

    @property
    def broadcast(self):
        """ Return the broadcast address in textual representation

        """
        return str(self.net.broadcast())

    @property
    def prefix(self):
        """ Return the network as an IPy.IP

        """
        return self.net.net()

    @property
    def prefixlen(self):
        """ Return the prefix length as an integer

        """
        return self.net.prefixlen()

    @staticmethod
    def _make_eui64(net, mac):
        """ Compute an EUI-64 address from an EUI-48 (MAC) address

        """
        if mac is None:
            return None
        comp = mac.split(":")
        prefix = IPy.IP(net).net().strFullsize().split(":")[:4]
        eui64 = comp[:3] + ["ff", "fe"] + comp[3:]
        eui64[0] = "%02x" % (int(eui64[0], 16) ^ 0x02)
        for l in range(0, len(eui64), 2):
            prefix += ["".join(eui64[l:l+2])]
        return IPy.IP(":".join(prefix))

    def make_ll64(self, mac):
        """ Compute an IPv6 Link-local address from an EUI-48 (MAC) address

        """
        return self._make_eui64("fe80::", mac)


class BindingConfig(object):
    def __init__(self, tap=None, indev=None,
                 mac=None, ip=None, hostname=None,
                 subnet=None, gateway=None,
                 subnet6=None, gateway6=None, eui64=None,
                 macspoof=None, mtu=None, private=None):
        self.mac = mac
        self.ip = ip
        self.hostname = hostname
        self.indev = indev
        self.tap = tap
        self.subnet = subnet
        self.gateway = gateway
        self.net = Subnet(net=subnet, gw=gateway, dev=tap)
        self.subnet6 = subnet6
        self.gateway6 = gateway6
        self.net6 = Subnet(net=subnet6, gw=gateway6, dev=tap)
        self.eui64 = eui64
        self.open_socket()
        self.macspoof = macspoof
        self.mtu = mtu
        self.private = private

    def is_valid(self):
        return self.mac is not None and self.hostname is not None


    def open_socket(self):

        logging.debug(" - Opening L2 socket and binding to %s", self.tap)
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, ETH_P_ALL)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
            s.bind((self.tap, ETH_P_ALL))
            self.socket = s
        except socket.error, e:
            logging.warning(" - Cannot open socket %s", e)


    def sendp(self, data):

        if isinstance(data, BasePacket):
            data = str(data)

        #logging.debug(" - Sending raw packet %r", data)

        try:
            count = self.socket.send(data, socket.MSG_DONTWAIT)
        except socket.error, e:
            logging.warn(" - Send with MSG_DONTWAIT failed: %s", str(e))
            self.socket.close()
            self.open_socket()
            raise e

        ldata = len(data)
        logging.debug(" - Sent %d bytes on %s", count, self.tap)
        if count != ldata:
            logging.warn(" - Truncated msg: %d/%d bytes sent",
                         count, ldata)

    def __repr__(self):
        ret =  "hostname %s, tap %s, mac %s" % \
               (self.hostname, self.tap, self.mac)
        if self.ip:
            ret += ", ip %s" % self.ip
        if self.eui64:
            ret += ", eui64 %s" % self.eui64
        return ret

    @staticmethod
    def load(path):
        """ Read a configuration binding file

        """
        logging.info("Parsing binding file %s", path)
        try:
            iffile = open(path, 'r')
        except EnvironmentError, e:
            logging.warn(" - Unable to open binding file %s: %s", path, str(e))
            return None

        def get_value(line):
            v = line.strip().split('=')[1]
            if v == '':
                return None
            return v

        try:
            tap = os.path.basename(path)
            indev = None
            mac = None
            ip = None
            hostname = None
            subnet = None
            gateway = None
            subnet6 = None
            gateway6 = None
            eui64 = None
            macspoof = None
            mtu = None
            private = None

            for line in iffile:
                if line.startswith("IP="):
                    ip = get_value(line)
                elif line.startswith("MAC="):
                    mac = get_value(line)
                elif line.startswith("HOSTNAME="):
                    hostname = get_value(line)
                elif line.startswith("INDEV="):
                    indev = get_value(line)
                elif line.startswith("SUBNET="):
                    subnet = get_value(line)
                elif line.startswith("GATEWAY="):
                    gateway = get_value(line)
                elif line.startswith("SUBNET6="):
                    subnet6 = get_value(line)
                elif line.startswith("GATEWAY6="):
                    gateway6 = get_value(line)
                elif line.startswith("EUI64="):
                    eui64 = get_value(line)
                elif line.startswith("MACSPOOF="):
                    macspoof = get_value(line)
                elif line.startswith("MTU="):
                    mtu = int(get_value(line))
                elif line.startswith("PRIVATE="):
                    private = get_value(line)
        finally:
            iffile.close()

        try:
            return BindingConfig(tap=tap, mac=mac, ip=ip, hostname=hostname,
                                 indev=indev, subnet=subnet, gateway=gateway,
                                 subnet6=subnet6, gateway6=gateway6,
                                 eui64=eui64, macspoof=macspoof, mtu=mtu,
                                 private=private)
        except ValueError:
            logging.warning(" - Cannot add client for host %s and IP %s on tap %s",
                            hostname, ip, tap)
            return None

