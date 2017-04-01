.. nfdhcpd documentation master file, created by
   sphinx-quickstart on Mon Jan 20 18:25:17 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to nfdhcpd's documentation!
===================================

nfdhcpd is a userspace daemon written in python and based on NFQUEUE [1] meant
to process DHCP, IPv6 Neighbor Solicitations (NS), IPv6 Router Solicitations (RS)
and DHCPv6 requests. The daemon should run on the hosts of virtualization environments
in order to directly reply to VMs' requests without these leaving the hosts. An
administrator can enable processing of those requests on individual TAP interfaces
by injecting nfdhcpd in the processing pipeline for IP packets dynamically (by
mangling the corresponding packet types and redirecting them to the appropriate
nfqueue).

nfdhcpd is mainly targeted to be used in a routed setup [2], where the
instances are not on the same collision domain with the external router,
but that does not mean it can't be used on bridged setup, even though one
might consider it a bit redundant.

The daemon is controlled by manipulating files under its state directory.
Creation of a new file under this directory ("binding file") instructs the daemon
to reply to the requests arriving on the specified TAP interface.

nfdhcpd vs. dnsmasq
-------------------

a) The service can be activated dynamically, per-interface, by manipulating
iptables accordingly. There is no need to restart the daemon, or edit
(potentially read-only) configuration files, you only need to drop a file
containing the required information under `/var/lib/nfdhcpd`.

b) There is no interference to existing DHCP servers listening to port
67. Everything happens directly via NFQUEUE.

c) The host doesn't even need to have an IP address on the interfaces
where DHCP replies are served, making it invisible to the VMs. This
may be beneficial from a security perspective. Similarly, it doesn't
matter if the TAP interface is bridged or routed.

d) Binding files provide a TAP-MAC mapping. In other words, requests coming
from unregistered TAP interfaces (without a binding file) are ignored, and
packet processing happens as if nfdhcpd didn't exist in the first place.
Requests coming from a registered device with but with different are considered
as snooping attempts and are dropped.

e) nfdhcpd is written in pure Python and uses scapy for packet
processing. This has proved to be super-useful when trying to troubleshoot
networking problems in production environments.

A simple DHCP scenario
----------------------

a) nfdhcpd starts. Upon initialization, it creates an NFQUEUE (e.g. 42) and listens
on it for incoming DHCP requests. It also begins to watch its state directory,
`/var/lib/nfdhcpd` via inotify().

b) A new VM gets created, let's assume that its NIC has address mac0, lives on TAP
interface tap0, and is to receive IP address ip0 via DHCP.

c) Someone (e.g., a Ganeti KVM ifup script, or in our case gnt-network [3]
creates a new binding file informing nfdhcpd that the daemon is to reply to DHCP
requests from MAC mac0 on TAP interface tap0, and include IP ip0 in the DHCP
reply.

d) The ifup script or the administrator injects nfdhcpd in the processing
pipeline for packets coming from tap0, using iptables:

.. code-block:: console

  # iptables -t mangle -A PREROUTING -p udp -m physdev --physdev-in tap+ -m udp --dport 67 -j NFQUEUE --queue-num 42

e) From now on, whenever a DHCP request is sent out by the VM, the
iptables rule will direct the packet to nfdhcpd, which will consult
its bindings database, find the entry for tap0, verify the source MAC,
and inject a DHCP reply for the corresponding IP address into tap0.

Binding file
------------

A binding file in nfdhcpd's state directory is named after the
physical interface where the daemon is to receive incoming DHCP requests
from, and defines at least the following variables:

* ``INSTANCE``: The instance name related to this interface

* ``INDEV``: The logical interface where the packet is received on. For
  bridged setups, the bridge interface, e.g., br0. Otherwise, same as
  the file name.

* ``MAC``: The MAC address where the DHCP request must be originating from

* ``IP``: The IPv4 address to be returned in DHCP replies

* ``SUBNET``: The IPv4 subnet to be returned in DHCP replies in CIDR form

* ``GATEWAY``: The IPv4 gateway to be returned in DHCP replies

* ``SUBNET6``: The IPv6 network prefix

* ``GATEWAY6``: The IPv6 network gateway

* ``EUI64``: The IPv6 address of the instance


nfdhcpd.conf
------------

The configuration file for nfdhcp is `/etc/nfdhpcd/nfdhcpd.conf`. Three
sections are defined: general, dhcp, ipv6.

Note that nfdhcpd can run as user `nobody`. This and other options related
to it's execution environment can be defined in section `general`.

In the `dhcp` section one defines the options related to DHCP replies.
Specifically:

* ``enable_dhcp`` to globally enable/disable DHCP

* ``server_ip`` a dummy IP used as source IP of the replies

* ``dhcp_queue`` the NFQUEUE number to listen on for DHCP requests

| Please not that this queue *must* be used in the iptables mangle rule later on.

* ``nameservers`` IPv4 nameservers to be included in DHCP replies

* ``domain`` the domain to serve with the replies (optional)

| If not given the instance's name (hostname) will be used instead.

In the `ipv6` section we define the options related to IPv6 responses.  Currently
nfdhcpd supports IPv6 stateless configuration [4] with or without DHCPv6. The
instance will get an auto-generated IPv6 (MAC to `EUI64`) based on the IPv6
prefix exported by Router Advertisements (`M flag` unset). If the `O flag` is set
(`nfdhcpd` is running in `SLAAC+DHCPv6` mode) the RA will make the instance
query for nameservers and domain search list via DHCPv6 request.
As previously said, nfdhcpd, currently and in case of IPv6, is supposed to work
on a routed setup thus any RA/NA requests should be served locally by the host.

Specifically:

* ``enable_ipv6`` to globally enable/disable IPv6 processing

* ``ra_period`` to define how often nfdhcpd will send RAs to TAPs that are IPv6 enabled

* ``rs_queue`` the NFQUEUE number to listen on for Router Solicitations (RS)

* ``ns_queue`` the NFQUEUE number to listen on for Neighbor Solicitations (NS)

* ``dhcpv6_queue`` the NFQUEUE number to listen on for DHCPv6 request

* ``mode`` to determine whether SLAAC or SLAAC+DHCPv6 is used

| This option may take one of the values: `slaac`, `slaac+dhcpv6` or `auto`, where the
| default one is `auto`. Right now Stateful DHCPv6 is not supported. If the
| value is `auto`, nfdhcpd will examine the provided NFQUEUE numbers to
| determine the running mode. If all three queues ({rs,ns,dhcpv6}_queue) are
| provided, the running mode will be `slaac+dhcpv6`. If only the router
| solicitation and neighbor solicitation queues are provided, then the running mode
| will be `slaac`.

* ``nameservers`` the IPv6 nameservers

| They can be sent using the RDNSS option of the RA [5] (if the `mode` is 
| set to `slaac`)  or serve them via DHCPv6 replies (if the `mode` is `slaac+dhcpv6`).
| RDNSS [6] is not supported by Windows. If you want to have full Windows support, the
| `mode` must be set to `slaac+dhcpv6`.

* ``domains`` the domain search list

| If not given the instance's name (hostname) will be used instead.

iptables rules
--------------

In order for nfdhcpd to be able to process incoming requests you have to mangle
the corresponding packets on the proper interface. Please note that in case of
a bridged setup you need to tell iptables to specifically match the packets
coming from the tap (physical indev) and not the bridge (logical indev).
Specifically:

* **DHCP**: ``iptables -t mangle -A PREROUTING -p udp -m physdev --physdev-in tap+ -m udp --dport 67 -j NFQUEUE --queue-num 42``

* **RS**: ``ip6tables -t mangle -A PREROUTING -i tap+ -p icmpv6 --icmpv6-type router-solicitation -j NFQUEUE --queue-num 43``

* **NS**: ``ip6tables -t mangle -A PREROUTING -i tap+ -p icmpv6 --icmpv6-type neighbour-solicitation -j NFQUEUE --queue-num 44``

* **DHCPv6**: ``ip6tables -t mangle -A PREROUTING -i tap+ -p udp --dport 547 -j NFQUEUE --queue-num 45``

The above example rules are placed by the package in `/etc/ferm/nfdhcpd.ferm`.
In case you use ferm, this file should be included by `/etc/ferm/ferm.conf`.
Otherwise an `rc.local` script can be used to issue those rules upon boot.


debugging
---------

To see all clients registered in nfdhpcd runtime context one can send SIGUSR1 and
see the list posted in the logfile:

.. code-block:: console

 # kill -SIGUSR1 $(cat /var/run/nfdhcpd/nfdhpcd.pid) && tail -n 100 /var/log/nfdhcpd/nfdhpcd.log


| [1] https://github.com/chifflier/nfqueue-bindings/
| [2] https://wiki.xen.org/wiki/Vif-route
| [3] http://docs.ganeti.org/ganeti/current/html/man-gnt-network.html
| [4] https://tools.ietf.org/html/rfc4862
| [5] https://tools.ietf.org/html/rfc5006
| [6] https://tools.ietf.org/html/rfc6106
