nfdhcpd
=======

nfdcpd: A promiscuous, NFQUEUE-based DHCP, DHCPv6 and Router Advertisement server for virtual machine hosting

Overview
--------

nfdhpcd is a userspace server written in python and based on [NFQUEUE](https://www.wzdftpd.net/redmine/projects/nfqueue-bindings/wiki/). An
administrator can enable processing of DHCP, Neighbor Solicitations, Router Solicitations and DHCPv6 requests on individual TAP interfaces by
injecting nfdhcpd in the processing pipeline for IP packets dynamically (by mangling the corresponding packet types and redirect them to the
appropriate nfqueue). nfdhcpd periodically sends Router Advertisements to all IPv6 enabled interfaces it monitors to enable addressing through
SLAAC. DHCPv6 functionality is currently limited to supplying Other Configuration data like DNS Recursive Name Server and Domain Search List as
supplementary to Router Advertisements.

The daemon runs on the host and is controlled by manipulating files under its state directory. Creation of a new file under this directory ("binding
file") instructs the daemon to reply on the requests arriving on the specified TAP interface. These files are meant to be created by the software
managing the instances on the host.

nfdhpcd is meant to work with [Ganeti](http://code.google.com/p/ganeti) and [snf-network](https://github.com/grnet/snf-network). Instances inside
the cluster will obtain their configuration dynamically in a completely transparent way without being aware of nfdhpcd's existence.

Binding Files
-------------
There's one binding file per network interface.

Here's a sample binding file (e.g. `/var/lib/nfdhcpd/tap10`):

```ini
INDEV=tap10
IP=192.0.2.100
MAC=aa:6b:39:22:33:44
HOSTNAME=testing-vm
TAGS=""
GATEWAY=192.0.2.1
SUBNET=192.0.2.0/24
GATEWAY6=2001:db8:aaaa:bbbb::1
SUBNET6=2001:db8:aaaa:bbbb::/64
EUI64=2001:db8:aaaa:bbbb:a86b:39ff:fe22:3344
PRIVATE=
```

Global configuration
--------------------

Here's a sample global configuration file (`/etc/nfdhcpd/nfdhcpd.conf`):

```ini
## nfdhcpd sample configuration file
## General options
[general]
pidfile = /var/run/nfdhcpd/nfdhcpd.pid
datapath = /var/lib/nfdhcpd # Where the client configuration will be read from
logdir = /var/log/nfdhcpd   # Where to write our logs
user = nobody # An unprivileged user to run as

## DHCP options
[dhcp]
enable_dhcp = yes
lease_lifetime = 604800 # 1 week
lease_renewal = 3600 	# 1 hour
server_ip = 192.0.2.1
server_on_link = no
dhcp_queue = 42 # NFQUEUE number to listen on for DHCP requests
# IPv4 nameservers to include in DHCP responses
nameservers = 192.0.2.2, 192.0.2.3
# Optional domain to serve with the replies
domain = example.com

## IPv6-related functionality
[ipv6]
enable_ipv6 = yes
enable_dhcpv6 = yes
ra_period = 300 # seconds
rs_queue = 43 # NFQUEUE number to listen on for router solicitations
ns_queue = 44 # NFQUEUE number to listen on for neighbor solicitations
dhcpv6_queue = 45 # NFQUEUE number to listen on for DHCPv6 Information-Requests
# IPv6 nameservers to send using the ICMPv6 RA RDNSS option (RFC 5006)
# since it is not supported by several OS we serve them to DHCPv6 replies
nameservers = 2001:db8:100::1, 2001:db8:200::2
domains = example.com
```

Packet filtering rules
----------------------

To send packets to `nfdhcpd` for processing, one must configure a few packet filtering rules. To process packets coming from TAP interfaces that
are members of bridges one needs to use the `-m physdev` option of iptables. There's a sample `ferm` ruleset in `contrib/ferm` directory. 

iptables for DHCP:
```shell
iptables -A PREROUTING -i tap+ -p udp -m udp --dport 67 -j NFQUEUE --queue-num 42
iptables -A PREROUTING -p udp -m physdev --physdev-in tap+ -m udp --dport 67 -j NFQUEUE --queue-num 42
```

ip6tables for RA,RS and DHCPv6:
```shell
ip6tables -A PREROUTING -i tap+ -p ipv6-icmp -m icmp6 --icmpv6-type 133 -j NFQUEUE --queue-num 43
ip6tables -A PREROUTING -i tap+ -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j NFQUEUE --queue-num 44
ip6tables -A PREROUTING -i tap+ -p udp -m udp --dport 547 -j NFQUEUE --queue-num 45
```

Debian packages
---------------


The `debian` branch can create a `.deb` file for installing on Debian-based distributions like Ubuntu. Run the following command to make the
package:

```shell
dpkg-buildpackage -us -uc 
```

*Warning for Debian users*: 
 * DHCPv6 functionality needs `python-scapy>2.3` and one currently needs to get a package from `Debian stretch`.
 * for physindev functionality to work you need `python-nfqueue>0.5` package. `Debian Jessie` package is fine.

You can find patched python-scapy and python-nfqueue packages for `Debian Wheezy` in [apt.dev.grnet.gr](http://apt.dev.grnet.gr/)

Acknowledgements
----------------

This codebase has been created by merging the original [nfdhcpd](https://code.grnet.gr/projects/nfdhcpd) code with
[snf-nfdhcpd](https://github.com/grnet/snf-nfdhcpd) and [nfdhcpd](https://github.com/davedoesdev/nfdhcpd) by David Halls.
