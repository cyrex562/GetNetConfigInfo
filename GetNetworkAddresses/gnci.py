#!/usr/bin/env/python3

"""
Windows IP Configuration

   Host Name . . . . . . . . . . . . : deathwing
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : perfectafederal.local
                                       localdomain

Ethernet adapter Ethernet:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : This Killer Ethernet Controller connects you to the net
   Physical Address. . . . . . . . . : F8-CA-B8-25-25-52
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes

Ethernet adapter vEthernet (DockerNAT):

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Hyper-V Virtual Ethernet Adapter
   Physical Address. . . . . . . . . : 00-15-5D-20-01-00
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::75f0:22e8:a1f8:252c%16(Preferred)
   IPv4 Address. . . . . . . . . . . : 10.0.75.1(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :
   DNS Servers . . . . . . . . . . . : fec0:0:0:ffff::1%1
                                       fec0:0:0:ffff::2%1
                                       fec0:0:0:ffff::3%1
   NetBIOS over Tcpip. . . . . . . . : Enabled

Wireless LAN adapter Local Area Connection* 2:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Microsoft Wi-Fi Direct Virtual Adapter
   Physical Address. . . . . . . . . : 9E-B6-D0-04-74-7D
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes

Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . : skynet.local
   Description . . . . . . . . . . . : Killer Wireless-n|a|ac 1535 Wireless Network Adapter
   Physical Address. . . . . . . . . : 9E-B6-C0-04-5C-9F
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.249.0.119(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Lease Obtained. . . . . . . . . . : Saturday, 5 November, 2016 11:34:11
   Lease Expires . . . . . . . . . . : Saturday, 5 November, 2016 14:26:38
   Default Gateway . . . . . . . . . : 10.249.0.1
   DHCP Server . . . . . . . . . . . : 10.249.0.1
   DNS Servers . . . . . . . . . . . : 10.249.0.1
   NetBIOS over Tcpip. . . . . . . . : Enabled

Ethernet adapter Bluetooth Network Connection:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Bluetooth PAN HelpText
   Physical Address. . . . . . . . . : 9C-B6-D0-04-74-7E
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes

Tunnel adapter Teredo Tunneling Pseudo-Interface:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Teredo Tunneling Pseudo-Interface
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
"""

import netifaces
import sys
import subprocess
from collections import namedtuple
import re
import logging
import logging.handlers

g_logger = logging.getLogger()
g_logger.setLevel(logging.DEBUG)
std_formatter = logging.Formatter("{asctime} {module}: {funcName}: {levelname}: {message}", style="{")
stdout_handler = logging.StreamHandler(stream=sys.stdout)
stdout_handler.setFormatter(std_formatter)
stdout_handler.setLevel(logging.DEBUG)
g_logger.addHandler(stdout_handler)
stderr_handler = logging.StreamHandler(stream=sys.stderr)
stderr_handler.setFormatter(std_formatter)
stderr_handler.setLevel(logging.WARNING)
g_logger.addHandler(stderr_handler)


def win_ipconfig():
    """
    Calls the windows command line tool ipconfig with the "/all" argument. Parses the printed output into a sequence of dictionaries like:
    [ { "name": "entry_name", "properties": {"entry_property": "...", ...,}}, ...]
    Discovered entry properties include:
        subnet_mask, 
        primary_dns_suffix,
        media_state,
        description,
        link_local_ipv6_address,
        ipv6_address,
        dhcpv6_iaid,
        autocnofiguration_enabled,
        host_name,
        ipv4_address,
        node_type,
        wins_proxy_enabled,
        dhcpv6_client_duid,
        connection_specific_dns_suffix,
        dhcp_enabled,
        dns_suffix_search_list,
        dns_servers,
        default_gateway,
        lease_obtained,
        lease_expires,
        netbios_over_tcpip,
        ip_routing_enabled,
        physical_address,
        dhcp_server
    """
    ipconfig_output = ""
    entries = []
    property_key_set = set()
    # call ipconfig
    try:
        result = subprocess.run(
            #["ipconfig", "/all"], 
            "ipconfig /all",
            check=True, 
            shell=True,
            stdout=subprocess.PIPE)
        ipconfig_output = result.stdout.decode("utf-8")
    except subprocess.CalledProcessError as cpe:
        sys.stderr("call to ipconfig failed")
        return entries

    # process the ipconfig output
    lines = ipconfig_output.split("\r\n")
    a = ipconfig_output.replace('\r\n', '\t')
    a = a.strip('\t')
    a = re.sub(r' ?(\. )+', '', a)
    a = re.sub(r' :', ':', a)
    a = re.sub(r'\t\t(?=[A-Za-z])', '\r\n', a)
    a = re.sub(r': \t', ': EMPTY\t', a)
    a = re.sub(r'\t {4,}', ',', a)
    a = re.sub(r'\t +', '\t', a)
    a = re.sub(r'(?<=[A-Za-z])\t\t', ':\t\t', a)
    b = a.split('\r\n')
    
    # convert the ipconfig output into a dict
    

    for c in b:
        name, properties = c.split('\t\t')
        properties = properties.split('\t')
        props_dict = {}
        for p in properties:
            if ':' in p:
                key, value = re.split(':', p, maxsplit=1)
                key = key.strip().lower()
                key = re.sub(r'[^a-zA-Z0-9]', '_', key) 
                property_key_set.add(key)
                v = value.strip()
                if "," in v:
                    v = v.split(',')
                props_dict[key] = v
        entry = dict(name=name.strip(':'), properties=props_dict)
        entries.append(entry)

    g_logger.debug("unique properties: {}".format(", ".join(property_key_set)))

    return entries

def run():
    interfaces = []
    out_interfaces = []

    for ifc_name in netifaces.interfaces():
        addrs = netifaces.ifaddresses(ifc_name)
        if netifaces.AF_INET in addrs and netifaces.AF_LINK in addrs:
            mac_addrs = addrs[netifaces.AF_LINK]
            ipv4_addrs = addrs[netifaces.AF_INET]
        
            ifc_dict = dict(ifc_name=ifc_name, mac_addrs=mac_addrs, ipv4_addrs=ipv4_addrs)
            interfaces.append(ifc_dict)

    if sys.platform == "win32":
        ipconfig_output = win_ipconfig()

        for ifc in interfaces:
            out_interfaces.append(dict(ifc_name=ifc["ifc_name"],
                                           ipv4_addrs=ifc["ipv4_addrs"],
                                           mac_addrs=ifc["mac_addrs"],
                                           name="",
                                           properties={}))
                                           #name=ipcoe_match["name"],
                                           #properties=ipcoe_match["properties"]))
        for ipcoe in ipconfig_output:
            ipcoe_updated = False
            for ofc in out_interfaces:
                 for mac in ofc["mac_addrs"]:
                     if "physical_address" in ipcoe["properties"]:
                         ipcoe_mac = ipcoe["properties"]["physical_address"].replace("-",":").lower()
                         if ipcoe_mac == mac["addr"]:
                             ofc["name"] = ipcoe["name"]
                             ofc["properties"] = ipcoe["properties"]
                             ipcoe_updated = True
            if ipcoe_updated is False:
                out_interfaces.append(dict(ifc_name="",
                                           ipv4_addrs=[],
                                           mac_addrs=[],
                                           name=ipcoe["name"],
                                           properties=ipcoe["properties"]))


        #for ifc in interfaces:
        #    ipcoe_match = None
        #    for mac in ifc["mac_addrs"]:
        #        for ipcoe in ipconfig_output:
        #            if "physical_address" in ipcoe["properties"]:
        #                ipcoe_mac = ipcoe["properties"]["physical_address"].replace("-",":").lower()
        #                if ipcoe_mac == mac["addr"]:
        #                    ipcoe_match = ipcoe
        #                    break
        #        if ipcoe_match is not None:
        #            break
        #    if ipcoe_match is not None:
        #        out_interfaces.append(dict(ifc_name=ifc["ifc_name"],
        #                                   ipv4_addrs=ifc["ipv4_addrs"],
        #                                   mac_addres=ifc["mac_addrs"],
        #                                   name=ipcoe_match["name"],
        #                                   properties=ipcoe_match["properties"]))

    g_logger.debug("interface information:\n{}\n".format(out_interfaces))

    x = ""
    for ofc in out_interfaces:
        if ofc["name"] != "Windows IP Configuration":
            if "ipv4_address" in ofc["properties"]:
                ipv4 = ofc["properties"]["ipv4_address"]
            elif len(ofc["ipv4_addrs"]) > 0:
                ipv4 = ofc["ipv4_addrs"][0]["addr"]
            else:
                ipv4 = ""

            if "physical_address" in ofc["properties"]:
                mac = ofc["properties"]["physical_address"]
            elif len(ofc["mac_addrs"]) > 0:
                mac = ofc["mac_addrs"][0]["addr"]
            else:
                mac = ""

            name1 = ofc["ifc_name"]
            name2 = ofc["name"]

            #ipv4 = ofc["properties"].get("ipv4_address", ofc["ipv4_addrs"]["addr"])
            #mac = ofc["properties"].get("physical_address", ofc["mac_addrs"]["addr"])
        
            x += "{}, {}, {}, {}\n".format(name1, name2, ipv4, mac)

    g_logger.info(
        "interface addresses:\nname1, name2, ipv4 address, mac address\n{}\n"
        .format(x))

    sys.exit(0)

if __name__ == "__main__":
    run()