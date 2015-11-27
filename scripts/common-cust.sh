#!/bin/bash

# unconditionally reverse previously applied rules (if existent)
function flush_firewall_ganetimgr {
    subchain=vima_$INTERFACE

    # flush out old rules
    for domain in ip ip6; do
        # Match rules for both routed and bridged ifaces
        # It's easier than trying to guess what the interface previously was
        /sbin/${domain}tables -D FORWARD -m physdev --physdev-in $INTERFACE -j $subchain 2>/dev/null
        /sbin/${domain}tables -D FORWARD -i $INTERFACE -j $subchain 2>/dev/null
        /sbin/${domain}tables -F $subchain 2>/dev/null
        /sbin/${domain}tables -X $subchain 2>/dev/null
    done
    rm -f $GANETI_FERM/$INTERFACE
}

# pick a firewall profile per NIC, based on tags (and apply it)
function setup_firewall_ganetimgr {
    subchain=vima_$INTERFACE

    # collect info...
    # 20150831 This has been commented out because we now need isolation for
    #          bridged vlans as well.
    #if [[ "$LINK" = public* ]]; then
    #    IS_PUBLIC=1
    #fi

    VIMA_FIREWALL=1
    for tag in $TAGS; do
        if [[ "$tag" = vima:application:* ]]; then
            IS_VIMA_APPLICATION=1
        elif [ "$tag" = "vima:service:mail" ]; then
            SERVICE_MAIL=1
        elif [ "$tag" = "vima:isolate" ]; then
            ISOLATE=1
        elif [[ "$tag" = vima:whitelist_ip:* ]]; then
            WHITELIST_IP=`echo $tag | cut -d":" -f3-`
            echo $WHITELIST_IP | grep ":" 1>/dev/null 2>&1
            if [ "$?" -eq 0 ]; then
                WHITELIST_IPV6=$WHITELIST_IP
            else
                WHITELIST_IPV4=$WHITELIST_IP
            fi
        fi
    done

    # ...and make the decision
    # bailout early on non-public links
    # 20150831 This has been commented out because we now need isolation for
    #          bridged vlans as well.
    #test -z $IS_PUBLIC && return

    # better safe than sorry
    mkdir -p "$GANETI_FERM"
    rm -f $GANETI_FERM/$INTERFACE
    if [ $VIMA_FIREWALL -eq 1 ]; then
        # create different ferm configuration depending on bridged/routed mode
        if [ "$MODE" = "routed" ]; then
            FERM_MODE='interface'
        elif [ "$MODE" = "bridged" ]; then
            FERM_MODE='mod physdev physdev-in'
        fi

        # Create a single jump because multiple @subchain declarations
        # create multiple '-N subchain' rules which result in error.
        # But we need at least a single "chain $subchain" rule applied to create
        # the necessary subchain. Else jump fails. That is the SERVICE_MAIL rule.
        cat >>"$GANETI_FERM/$INTERFACE" <<EOF
    domain (ip ip6) chain FORWARD { $FERM_MODE $INTERFACE jump "$subchain"; }
EOF
        # SERVICE_MAIL is only for routed networks, don't filter port 25 on
        # bridged networks
        if [ -z "$SERVICE_MAIL" -a "$MODE" = "routed"]; then
            cat >>"$GANETI_FERM/$INTERFACE" <<EOF
    domain (ip ip6) chain "$subchain" $FERM_MODE $INTERFACE {
        proto tcp dport 25 REJECT;
    }
EOF
        else # Can't have empty jump (chain X, creates chain if it doesn't exist)
            cat >>"$GANETI_FERM/$INTERFACE" <<EOF
    domain (ip ip6) chain "$subchain" $FERM_MODE $INTERFACE {
        proto tcp dport 25 ACCEPT;
    }
EOF
        fi  
        if [ -n "$WHITELIST_IPV6" ]; then
            cat >>"$GANETI_FERM/$INTERFACE" <<EOF
    domain (ip6) chain "$subchain" $FERM_MODE $INTERFACE {
        proto all saddr $WHITELIST_IPV6 ACCEPT;
        proto all daddr $WHITELIST_IPV6 ACCEPT;
    }
EOF
        fi  
        if [ -n "$WHITELIST_IPV4" ]; then
            cat >>"$GANETI_FERM/$INTERFACE" <<EOF
    domain (ip) chain "$subchain" $FERM_MODE $INTERFACE {
        proto all saddr $WHITELIST_IPV4 ACCEPT;
        proto all daddr $WHITELIST_IPV4 ACCEPT;
    }
EOF
        fi  
        if [ -n "$ISOLATE" ]; then
            cat >>"$GANETI_FERM/$INTERFACE" <<EOF
    domain (ip ip6) chain "$subchain" $FERM_MODE $INTERFACE {
        DROP;
    }
EOF
        fi  
        if [ -s "$GANETI_FERM/$INTERFACE" ]; then
            ferm --slow --noflush "$GANETI_FERM/$INTERFACE"
        fi  
    fi  
}

function permit_nfdhcpd_mac_spoofing {
    local our_tag=vima:nfdhcpd_mac_spoof_ifce
    for tag in $TAGS; do
        if [[ "$tag" = "$our_tag":* ]]; then
            if [ "$INTERFACE_INDEX" == "${tag#${our_tag}:}" ]; then
                MACSPOOF=1
                break
            fi
        fi
    done
}
