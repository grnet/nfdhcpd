#!/usr/bin/env python
#

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

"""nfdcpd: A promiscuous, NFQUEUE-based DHCP, DHCPv6 and Router Advertisement
server for virtual machine hosting.
"""

import os
import signal
import sys
import logging
import logging.handlers
import traceback
import argparse
import cStringIO
import pwd

import daemon
import daemon.runner
try:
    # For daemon >= 1.6
    # pylint: disable=no-name-in-module,import-error
    import daemon.pidfile as pidlockfile
except ImportError:
    # For daemon < 1.6
    # pylint: disable=no-name-in-module,import-error
    import daemon.pidlockfile as pidlockfile

import setproctitle
import lockfile
import IPy
import capng
import configobj
import validate

from nfdhcpd.vm_net_proxy import VMNetProxy
from nfdhcpd.version import __version__

DEFAULT_CONFIG = "/etc/nfdhcpd/nfdhcpd.conf"
LOG_FILENAME = "nfdhcpd.log"
LOG_FORMAT = "%(asctime)-15s %(levelname)-8s %(message)s"

# Configuration file specification (see configobj documentation)
CONFIG_SPEC = """
[general]
pidfile = string()
datapath = string()
logdir = string()
user = string()

[dhcp]
enable_dhcp = boolean(default=True)
lease_lifetime = integer(min=0, max=4294967295)
lease_renewal = integer(min=0, max=4294967295)
server_ip = ip_addr()
server_on_link = boolean(default=False)
dhcp_queue = integer(min=0, max=65535)
nameservers = ip_addr_list(family=4)
domain = string(default=None)

[ipv6]
enable_ipv6 = boolean(default=True)
enable_dhcpv6 = boolean(default=False)
ra_period = integer(min=1, max=4294967295)
rs_queue = integer(min=0, max=65535)
ns_queue = integer(min=0, max=65535)
dhcp_queue = integer(min=0, max=65535, default=None)
dhcpv6_queue = integer(min=0, max=65535, default=None)
nameservers = ip_addr_list(family=6)
domains = force_list(default=None)
"""


def is_ip_list(value, family=4):
    """Validation function for IP & IPv6 lists"""
    try:
        family = int(family)
    except ValueError:
        raise validate.VdtParamError("family", family)
    if isinstance(value, (str, unicode)):
        value = [value]
    if not isinstance(value, list):
        raise validate.VdtTypeError(value)

    for entry in value:
        try:
            ip = IPy.IP(entry)
        except ValueError:
            raise validate.VdtValueError(entry)

        if ip.version() != family:
            raise validate.VdtValueError(entry)
    return value


def main():
    """Main nfdhcpd entry point"""
    validator = validate.Validator()

    validator.functions["ip_addr_list"] = is_ip_list
    config_spec = cStringIO.StringIO(CONFIG_SPEC)

    parser = argparse.ArgumentParser(description=__doc__, version=__version__)
    parser.add_argument(
        "-c", "--config", dest="config_file", metavar="FILE",
        help="The location of the configuration file [%s]" % DEFAULT_CONFIG,
        default=DEFAULT_CONFIG)
    parser.add_argument(
        "-d", "--debug", action="store_true", dest="debug", default=False,
        help="Turn on debugging messages")
    parser.add_argument(
        "-f", "--foreground", action="store_false", default=True,
        dest="daemonize", help="Do not daemonize, stay in the foreground")

    opts = parser.parse_args()

    try:
        config = configobj.ConfigObj(opts.config_file, configspec=config_spec)
    except configobj.ConfigObjError as err:
        sys.stderr.write("Failed to parse config file %s: %s" %
                         (opts.config_file, str(err)))
        sys.exit(1)

    results = config.validate(validator)
    if results is not True:
        logging.fatal(
            "Configuration file validation failed! See errors below:")
        for (section_list, key, _) in configobj.flatten_errors(config,
                                                               results):
            if key is not None:
                logging.fatal(" '%s' in section '%s' failed validation",
                              key, ", ".join(section_list))
            else:
                logging.fatal(" Section '%s' is missing",
                              ", ".join(section_list))
        sys.exit(1)

    try:
        uid = pwd.getpwuid(config["general"].as_int("user"))
    except ValueError:
        uid = pwd.getpwnam(config["general"]["user"])

    # Keep only the capabilities we need
    # CAP_NET_ADMIN: we need to send nfqueue packet verdicts to a netlinkgroup
    # CAP_NET_RAW: we need to reopen socket in case the buffer gets full
    # CAP_SETPCAP: needed by capng_change_id()
    capng.capng_clear(capng.CAPNG_SELECT_BOTH)
    capng.capng_update(capng.CAPNG_ADD,
                       capng.CAPNG_EFFECTIVE | capng.CAPNG_PERMITTED,
                       capng.CAP_NET_ADMIN)
    capng.capng_update(capng.CAPNG_ADD,
                       capng.CAPNG_EFFECTIVE | capng.CAPNG_PERMITTED,
                       capng.CAP_NET_RAW)
    capng.capng_update(capng.CAPNG_ADD,
                       capng.CAPNG_EFFECTIVE | capng.CAPNG_PERMITTED,
                       capng.CAP_SETPCAP)
    # change uid
    capng.capng_change_id(uid.pw_uid, uid.pw_gid,
                          capng.CAPNG_DROP_SUPP_GRP |
                          capng.CAPNG_CLEAR_BOUNDING)

    logger = logging.getLogger()
    if opts.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if opts.daemonize:
        logfile = os.path.join(config["general"]["logdir"], LOG_FILENAME)
        try:
            handler = logging.handlers.WatchedFileHandler(logfile)
        except IOError:
            sys.stderr.write(" - Failed to open logging directory, exiting.\n")
            sys.exit(1)
    else:
        handler = logging.StreamHandler()

    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logger.addHandler(handler)

    # Rename this process so 'ps' output looks like
    # this is a native executable.
    # NOTE: due to a bug in python-setproctitle, one cannot yet
    # set individual values for command-line arguments, so only show
    # the name of the executable instead.
    # setproctitle.setproctitle("\x00".join(sys.argv))
    setproctitle.setproctitle(sys.argv[0])  # pylint: disable=no-member

    if opts.daemonize:
        pidfile = pidlockfile.TimeoutPIDLockFile(
            config["general"]["pidfile"], 10)
        # Remove any stale PID files, left behind by previous invocations
        if daemon.runner.is_pidfile_stale(pidfile):
            logger.warning("Removing stale PID lock file %s", pidfile.path)
            pidfile.break_lock()

        d = daemon.DaemonContext(pidfile=pidfile,
                                 umask=0022,
                                 stdout=handler.stream,
                                 stderr=handler.stream,
                                 files_preserve=[handler.stream])
        try:
            d.open()
            # daemon internally uses lockfile and does not re-wrap the lockfile
            # exceptions.
        except lockfile.LockError as e:
            logger.critical("Failed to lock pidfile: %s. Reason: %s",
                            pidfile.path, str(e))
            sys.exit(1)

    logging.info("Starting up nfdhcpd v%s", __version__)
    logging.info("Running as %s (uid:%d, gid: %d)",
                 config["general"]["user"], uid.pw_uid, uid.pw_gid)

    proxy_opts = {}
    if config["dhcp"].as_bool("enable_dhcp"):
        proxy_opts.update({
            "dhcp_queue_num": config["dhcp"].as_int("dhcp_queue"),
            "dhcp_lease_lifetime": config["dhcp"].as_int("lease_lifetime"),
            "dhcp_lease_renewal": config["dhcp"].as_int("lease_renewal"),
            "dhcp_server_ip": config["dhcp"]["server_ip"],
            "dhcp_server_on_link": config["dhcp"]["server_on_link"],
            "dhcp_nameservers": config["dhcp"]["nameservers"],
            "dhcp_domain": config["dhcp"]["domain"],
        })

    if config["ipv6"].as_bool("enable_ipv6"):
        proxy_opts.update({
            "rs_queue_num": config["ipv6"].as_int("rs_queue"),
            "ns_queue_num": config["ipv6"].as_int("ns_queue"),
            "ra_period": config["ipv6"].as_int("ra_period"),
            "ipv6_nameservers": config["ipv6"]["nameservers"],
            "dhcpv6_domains": config["ipv6"]["domains"],
        })

    if config["ipv6"].as_bool("enable_ipv6") and \
            config["ipv6"].as_bool("enable_dhcpv6"):
        try:
            transition_dhcpv6_queue = config["ipv6"].as_int("dhcpv6_queue")
        except:
            transition_dhcpv6_queue = config["ipv6"].as_int("dhcp_queue")
        proxy_opts.update({"dhcpv6_queue_num": transition_dhcpv6_queue})

    # pylint: disable=star-args
    proxy = VMNetProxy(data_path=config["general"]["datapath"], **proxy_opts)

    logging.info("Ready to serve requests")

    def debug_handler(signum, _):
        logging.debug('Received signal %d. Printing proxy state...', signum)
        proxy.print_clients()

    # Set the signal handler for debuging clients
    signal.signal(signal.SIGUSR1, debug_handler)
    signal.siginterrupt(signal.SIGUSR1, False)

    try:
        proxy.serve()
    except Exception:
        if opts.daemonize:
            exc = "".join(traceback.format_exception(*sys.exc_info()))
            logging.critical(exc)
        raise


# vim: set ts=4 sts=4 sw=4 et :
