#!/usr/bin/env python3
"""Get BGP neighbours from network devices for PDB."""
import os
import sys
import pprint
import json
import ipaddress
import click


from napalm import get_network_driver

pp = pprint.PrettyPrinter(indent=2, width=120)

prog_args = {}


def parse_neighbours(neighbours):
    """Parse the bgp neighbours from network device.

    Args:
        neighbours (dict): Neighbour list.

    Returns:
        dict: Parsed neighbour list.
    """
    results = {}
    for neighbour in neighbours:
        addr = ipaddress.ip_address(neighbour)

        # If this is a private IP address then continue
        # unless the rfc1918 argument was given
        #
        if addr.is_private:
            if prog_args["verbose"] >= 2:
                print("DEBUG: Skipping neighbour {} with a " "private IP.".format(neighbour), file=sys.stderr)
            continue

        if prog_args["verbose"] >= 1:
            print("DEBUG: Found neighbour {}".format(neighbour), file=sys.stderr)

        ipversion = addr.version

        if ipversion == 4:
            address_family = "ipv4"
            if prog_args["verbose"] >= 2:
                print("DEBUG: Neighbour {} has an IPv4 address.".format(neighbour), file=sys.stderr)
        elif ipversion == 6:
            address_family = "ipv6"
            if prog_args["verbose"] >= 2:
                print("DEBUG: Neighbour {} has an IPv6 address.".format(neighbour), file=sys.stderr)
        else:
            print("ERROR: Can not find an address family for neighbour {}.".format(neighbour), file=sys.stderr)
            continue

        as_number = neighbours[neighbour]["remote_as"]

        if prog_args["asexcept"] and (as_number not in prog_args["asexcept"]):
            continue

        if prog_args["asignore"] and as_number in prog_args["asignore"]:
            continue

        results[neighbour] = {
            "as": as_number,
            "description": neighbours[neighbour]["description"],
            "ip_version": ipversion,
            "is_up": neighbours[neighbour]["is_up"],
            "is_enabled": neighbours[neighbour]["is_enabled"],
            "uptime": neighbours[neighbour]["uptime"],
            "dual_stack": False,
        }

        # Check to see if ipv4 and ipv6 is enabled on this neighbour

        if neighbours[neighbour]["is_up"]:
            results[neighbour]["routes"] = {}
            results[neighbour]["routes"][address_family] = neighbours[neighbour]["address_family"][address_family]

            # IPv4 BGP neighbour with IPv6 routes.
            if ipversion == 4 and "ipv6" in neighbours[neighbour]["address_family"]:
                # If sent_prefixes is -1 then ipv6 routes are not enabled on this neighbour (mainly for JunOS)
                if neighbours[neighbour]["address_family"]["ipv6"]["sent_prefixes"] != -1:
                    results[neighbour]["routes"]["ipv6"] = neighbours[neighbour]["address_family"]["ipv6"]
                    results[neighbour]["dual_stack"] = True
                    if prog_args["verbose"] >= 2:
                        print("DEBUG: Neighbour {} is multi-protocol.".format(neighbour), file=sys.stderr)

            # IPv6 BGP neighbour with IPv4 routes.
            if ipversion == 6 and "ipv4" in neighbours[neighbour]["address_family"]:
                # If sent_prefixes is -1 then ipv4 routes are not enabled on this neighbour (mainly for JunOS)
                if neighbours[neighbour]["address_family"]["ipv4"]["sent_prefixes"] != -1:
                    results[neighbour]["routes"]["ipv4"] = neighbours[neighbour]["address_family"]["ipv4"]
                    results[neighbour]["dual_stack"] = True
                    if prog_args["verbose"] >= 2:
                        print("DEBUG: Neighbour {} is multi-protocol.".format(neighbour), file=sys.stderr)
        else:
            results[neighbour]["routes"] = None
            if prog_args["verbose"] >= 2:
                print("DEBUG: Neighbour {} is down.".format(neighbour), file=sys.stderr)

    return results


def get_neighbours(host, device_os, transport="ssh"):
    """Get BGP neighbours from network device.

    Args:
        host (str): Hostname of network device.
        device_os (str): OS of the network Device.
        transport (str, optional): Network device transport type. telnet or ssh. Defaults to "ssh".

    Returns:
        dict: BGP Neighbours from device.
    """
    optional_args = {"transport": transport.lower()}

    driver = get_network_driver(device_os)
    # Connect and open the device with napalm and run commands.
    #
    try:
        with driver(host, prog_args["username"], prog_args["password"], optional_args=optional_args) as device:
            return device.get_bgp_neighbors()
    except Exception as error_msg:
        print("ERROR: Connecting to {} failed: {}".format(host, error_msg), file=sys.stderr)
        return None


def do_device(hostname, device_os, transport="ssh"):
    """Connect to device and get the neighbours.

    Args:
        hostname (str): Hostname of network device
        device_os (str): OS of the network device
        transport (str, optional): Network device transport either ssh or telnet. Defaults to "ssh".

    Returns:
        dict: BGP neighbours on device.
    """

    neighbours = get_neighbours(hostname, device_os, transport)

    if neighbours:
        if "global" in neighbours:
            return parse_neighbours(neighbours["global"]['peers'])

    print("DEBUG: No BGP neighbours found on {}".format(hostname), file=sys.stderr)

    return {}


@click.command()
@click.option(
    "--username",
    type=str,
    required=True,
    metavar="USERNAME",
    help="Username to log into router",
    envvar="BGPNEIGET_USERNAME",
)
@click.option(
    "--password",
    type=str,
    required=True,
    metavar="PASSWORD",
    help="Password to log into router",
    envvar="BGPNEIGET_PASSWORD",
)
@click.option(
    "--verbose", "-v", count=True, help="Output some debug information, use multiple times for increased verbosity."
)
@click.option(
    "-d",
    "--device",
    nargs=3,
    type=str,
    required=True,
    metavar=("HOSTNAME", "OS", "TRANSPORT"),
    help="Single device to connect to along with the device OS and transport (SSH or Telnet)",
)
@click.option(
    "--asexcept",
    type=int,
    metavar="ASNUM",
    multiple=True,
    help="Filter out all AS number except this one. Can be used multiple times.",
)
@click.option(
    "--asignore", type=int, metavar="ASNUM", multiple=True, help="AS number to filter out. Can be used multiple times."
)
def cli(**cli_args):
    """Entry point for command.

    Raises:
        SystemExit: Error in command line options
    """
    global prog_args

    prog_args = cli_args

    if prog_args["asignore"] and prog_args["asexcept"]:

        raise SystemExit(
            "{} error: argument --asignore: not allowed" " with argument --asexcept".format(os.path.basename(__file__))
        )

    supported_os = ["ios", "ios-xr", "junos", "eos"]

    if prog_args["device"][1].lower() not in supported_os:
        raise SystemExit("ERROR: OS ({})is not supported.".format(prog_args["device"][1]))

    devices_results = do_device(
        prog_args["device"][0], prog_args["device"][1], prog_args["device"][2]
    )
    if prog_args["verbose"] >= 2:
        print("Current memory usage of results dictionary: {}".format(sys.getsizeof(devices_results)))

    print(json.dumps(devices_results, indent=2))

    if prog_args["verbose"] >= 2:
        print("Current memory usage of results dictionary: {}".format(sys.getsizeof(devices_results)))
