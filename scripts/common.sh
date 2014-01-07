#!/bin/bash

if [ -e /usr/lib/nfdhcpd/common-cust.sh ]; then
    source /usr/lib/nfdhcpd/common-cust.sh
fi

function try {

  $1 &>/dev/null || true 

}


function clear_routed_setup_ipv4 {

 arptables -D OUTPUT -o $INTERFACE --opcode request -j mangle
 while ip rule del dev $INTERFACE; do :; done
 iptables -D FORWARD -i $INTERFACE -p udp --dport 67 -j DROP

}

function clear_routed_setup_ipv6 {

 while ip -6 rule del dev $INTERFACE; do :; done

}


function clear_routed_setup_firewall {

  for oldchain in protected unprotected limited; do
    iptables  -D FORWARD -o $INTERFACE -j $oldchain
    ip6tables -D FORWARD -o $INTERFACE -j $oldchain
  done

}

function clear_ebtables {

  ebtables -D FORWARD -i $INTERFACE -j $FROM
  ebtables -D FORWARD -o $INTERFACE -j $TO
  #ebtables -D OUTPUT -o $INTERFACE -j $TO

  ebtables -X $FROM
  ebtables -X $TO
}


function clear_nfdhcpd {

  rm -f $NFDHCPD_STATE_DIR/$INTERFACE

}


function routed_setup_ipv4 {
    # get the link's default gateway
    if [ -z "$NETWORK_GATEWAY" ]; then
        # These are only needed with ganeti version < 2.7
        DEV=$(ip route list table $LINK | sed -n 's/default via .* dev \([^ ]\+\)/\1/p' | head -1)
        NETWORK_GATEWAY=$(ip route list table $LINK dev $DEV| grep "^default" | sed -n 's/^default via \([^ ]\+\) .*$/\1/p' | head -n1)
        NETWORK_SUBNET=$(ip route list table $LINK dev $DEV| head -n1 | sed -n 's/^\(.*\)  scope.*$/\1/p')
    fi

    # mangle ARPs to come from the gw's IP
    arptables -A OUTPUT -o $INTERFACE --opcode request -j mangle --mangle-ip-s "$NETWORK_GATEWAY"

    # route interface to the proper routing table
    ip rule add dev $INTERFACE table $TABLE

    # static route mapping IP -> INTERFACE
    ip route replace $IP proto static dev $INTERFACE table $TABLE

    # Enable proxy ARP
    echo 1 > /proc/sys/net/ipv4/conf/$INTERFACE/proxy_arp
}

function routed_setup_ipv6 {
    # Add a routing entry for the eui-64
    if [ -z "$NETWORK_GATEWAY6" ]; then
        # These are only needed whith ganeti version < 2.7
        NETWORK_DEV6=$(ip -6 route list table $LINK| grep "^default" | sed -n 's/^default via .* dev \([^ ]\+\) .*$/\1/p' | head -n1 )
        NETWORK_SUBNET6=$(ip -6 route list table $LINK | awk '/\/64/ {print $1; exit}')
        NETWORK_GATEWAY6=$(ip -6 route list table $LINK dev $DEV| grep "^default" | sed -n 's/^default via \([^ ]\+\) .*$/\1/p' | head -n1 )
    fi

    prefix=$NETWORK_SUBNET6
    uplink=$(ip -6 route list table $TABLE | grep "default via" | awk '{print $5}')
    eui64=$($MAC2EUI64 $MAC $prefix)


    ip -6 rule add dev $INTERFACE table $TABLE
    ip -6 ro replace $eui64/128 dev $INTERFACE table $TABLE
    ip -6 neigh add proxy $eui64 dev $uplink

    # disable proxy NDP since we're handling this on userspace
    # this should be the default, but better safe than sorry
    echo 0 > /proc/sys/net/ipv6/conf/$INTERFACE/proxy_ndp
}

# pick a firewall profile per NIC, based on tags (and apply it)
function routed_setup_firewall {
    ifprefix="synnefo:network:$INTERFACE_INDEX:"
    for tag in $TAGS; do
        case ${tag#$ifprefix} in
        protected)
            chain=protected
        ;;
        unprotected)
            chain=unprotected
        ;;
        limited)
            chain=limited
        ;;
        esac
    done

    if [ "x$chain" != "x" ]; then
        iptables  -A FORWARD -o $INTERFACE -j $chain
        ip6tables -A FORWARD -o $INTERFACE -j $chain
    fi
}

function init_ebtables {

  ebtables -N $FROM
  ebtables -A FORWARD -i $INTERFACE -j $FROM
  ebtables -N $TO
  ebtables -A FORWARD -o $INTERFACE -j $TO

}


function setup_ebtables {

  # do not allow changes in ip-mac pair
  if [ -n "$IP"]; then
    ebtables -A $FROM --ip-source \! $IP -p ipv4 -j DROP
  fi
  ebtables -A $FROM -s \! $MAC -j DROP
  #accept dhcp responses from host (nfdhcpd)
  ebtables -A $TO -p ipv4 --ip-protocol=udp  --ip-destination-port=68 -j ACCEPT
  # allow only packets from the same mac prefix
  ebtables -A $TO -s \! $MAC/$MAC_MASK -j DROP
}

function setup_masq {

  # allow packets from/to router (for masquerading)
  # ebtables -A $TO -s $NODE_MAC -j ACCEPT
  # ebtables -A INPUT -i $INTERFACE -j $FROM
  # ebtables -A OUTPUT -o $INTERFACE -j $TO
  return

}

function setup_nfdhcpd {
    umask 022
  FILE=$NFDHCPD_STATE_DIR/$INTERFACE
  #IFACE is the interface from which the packet seems to arrive
  #needed in bridged mode where the packets seems to arrive from the
  #bridge and not from the tap
    cat >$FILE <<EOF
INDEV=$INDEV
IP=$IP
MAC=$MAC
HOSTNAME=$INSTANCE
TAGS="$TAGS"
GATEWAY=$NETWORK_GATEWAY
SUBNET=$NETWORK_SUBNET
GATEWAY6=$NETWORK_GATEWAY6
SUBNET6=$NETWORK_SUBNET6
EUI64=$($MAC2EUI64 $MAC $NETWORK_SUBNET6 2>/dev/null)
EOF

}

