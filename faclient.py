#! /usr/bin/env python
from enum import Enum
from scapy.all import *
import getopt
import re
import socket
import struct
import sys
import time


# Initialize key variables
class ElementTypeMap(IntEnum):
	OTHER            = 1
	FA_SERVER        = 2
	FA_PROXY         = 3
	FA_SERVER_NOAUTH = 4
	FA_PROXY_NOAUTH  = 5
	CLIENT_WAP1      = 6
	CLIENT_WAP2      = 7
	CLIENT_SWITCH    = 8
	CLIENT_ROUTER    = 9
	CLIENT_PHONE     = 10
	CLIENT_CAMERA    = 11
	CLIENT_VIDEO     = 12
	CLIENT_SECURITY  = 13
	CLIENT_VSWITCH   = 14
	CLIENT_SERVER    = 15

assignmentMappings = None
elementType        = ElementTypeMap.FA_PROXY_NOAUTH
interfaceName      = None
mgmtVlan           = 0
ttl                = 120


# Argument handling
helpText = """FA Client Help.

Example command: faclient --assignmentMappings="(10:54320),(11:49920)" --elementType="FA_PROXY_NOAUTH" --interfaceName="Eth1" --managementVlan=0 --ttl=120


Corresponding short options can be also used: -a="(10:54320),(11:49920)" -e="FA_PROXY_NOAUTH" -i="Eth1" -m=0 -t=120

The only required field is interfaceName. assignmentMappings are optional additional VLAN requests, elementType will default to FA_PROXY_NOAUTH, managementVlan will default to 0 (untagged), and ttl will default to 120


assignmentMappings: Comma separated sets of (vlan:isid),(vlan:isid). Valid ranges (1-4095:1-15999999)

elementType: The numerical element type from 1-15 or the textual names:
- OTHER
- FA_SERVER
- FA_PROXY
- FA_SERVER_NOAUTH
- FA_PROXY_NOAUTH
- CLIENT_WAP1
- CLIENT_WAP2
- CLIENT_SWITCH
- CLIENT_ROUTER
- CLIENT_PHONE
- CLIENT_CAMERA
- CLIENT_VIDEO
- CLIENT_SECURITY
- CLIENT_VSWITCH
- CLIENT_SERVER

interfaceName: The textual name of the network adapter to use.

managementVLAN: The management VLAN 0-4095 to register the element with. Typically you want this to be 0 (untagged).

ttl: Time to live, 2-65535. Typically you want this to be 120 seconds. Too long and the entry may time out on the switch before being refreshed.
"""
shortOptions = "haeimt"
longOptions  = ["help", "assignmentMappings=", "elementType=", "interfaceName=", "managementVlan=", "ttl="]

if len(sys.argv) == 1 or sys.argv[1] == "--" or sys.argv[1] == "-":
	print(helpText)
	exit()
try:
	arguments, values = getopt.getopt(sys.argv[1:], shortOptions, longOptions)
except:
	print(helpText)
	exit()
# Process matching arguments
for currentArgument, currentValue in arguments:
	match currentArgument:
		case "--assignmentMappings" | "-a":
			# Check that the mappings are of the form (vlan:isid) with optional chainings of ,(vlan:isid)
			pattern = re.compile("^(\(([1-9]|[1-9]\d{1,2}|[1-3]\d{3}|40[0-8]\d|409[0-5]):([1-9]|[1-9]\d{1,6}|1[0-5]\d{6})\))(,\(([1-9]|[1-9]\d{1,2}|[1-3]\d{3}|40[0-8]\d|409[0-5]):([1-9]|[1-9]\d{1,6}|1[0-5]\d{6})\))*$")
			if not pattern.match(currentValue):
				print("Error: Invalid assignmentMappings list.")
				exit()
			else:
				# Since we know the mappings are in a valid format we can split them into an array and convert them to the internal format
				assignmentMappings = []
				assignmentStrings = currentValue.split(",")
				for assignment in assignmentStrings:
					pair = assignment.replace("(","").replace(")","").split(":")
					assignmentMappings.append((int(pair[0]), int(pair[1])))
		case "--elementType" | "-e":
			if currentValue.isnumeric():
				elementType = int(currentValue)
			else:
				try:
					elementType = elementTypeMap[currentValue].value
				except:
					print("Error: Invalid element type.")
					exit()
		case "--interfaceName" | "-i":
			interfaceName = currentValue
		case "--managementVlan" | "-m":
			if currentValue.isnumeric():
				mgmtVlan = int(currentValue)
			else:
				print("Error: Invalid managementVlan.")
				exit()
		case "--ttl" | "-t":
			if currentValue.isnumeric():
				ttl = int(ttl)
			else:
				print("Error: Invalid ttl.")
				exit()
		case _:
			print("Error: Impossible state reached in argument parsing on value. Probably a half configured option in the parser for: " + currentArgument + " " + currentValue)
			exit()


# Validation
deviceMac = get_if_hwaddr(interfaceName)
if deviceMac == "00:00:00:00:00:00":
	print("Error: interfaceName doesn't exist.")
	exit()

if ttl < 3 or ttl > 65535 or not isinstance(ttl, int):
	print("Error: ttl not in the range of 3-65535 seconds.")
	exit()

if elementType < 1 or elementType > 15 or not isinstance(elementType, int):
	print("Error: Invalid elementType, not 1-15 or one of the names listed in help.")
	exit()

if mgmtVlan < 0 or mgmtVlan > 4095 or not isinstance(mgmtVlan, int):
	print("Error: mgmtVlan not in the range of 3-65535 seconds.")
	exit()
# assignmentVlans


# Definition
# Set some dynamically assigned info
deviceMacNumber   = int(deviceMac.replace(":", ""), 16)
hostname          = socket.gethostname()
mgmtAddress       = get_if_addr(interfaceName)
mgmtAddressNumber = struct.unpack("!L", socket.inet_aton(mgmtAddress))[0]
systemDescription = "STEP CG Fabric-Attach Client 1.0"

class Lldp(Packet):
	name = "lldpPacket "
	fields_desc = [XBitField("chassisTlv",       0x1,             7),
	               XBitField("chassisLength",    0x7,             9),
	               XBitField("chassisIdSubType", 0x4,             8),
	               XBitField("chassisIdValue",   deviceMacNumber, 48),

	               XBitField("portTlv",       0x2,                          7),
	               XBitField("portLength",    len(interfaceName[:255]) + 1, 9),
	               XBitField("portIdSubType", 5,                            8),
	               StrField("portIdValue",    interfaceName[:255]),

	               XBitField("timeToLiveTlv",    0x3, 7),
	               XBitField("timeToLiveLength", 0x2, 9),
	               XBitField("timeToLiveValue",  ttl, 16),

	               XBitField("systemNameTlv",    0x5,                 7),
	               XBitField("systemNameLength", len(hostname[:255]), 9),
	               StrField("systemNameValue",   hostname),

	               XBitField("systemDescriptionTlv",    0x6,                          7),
	               XBitField("systemDescriptionLength", len(systemDescription[:255]), 9),
	               StrField("systemDescriptionValue",   systemDescription),

	               XBitField("capabilitiesTlv",           0x7, 7),
	               XBitField("capabilitiesLength",        0x4, 9),
	               XBitField("capabilityReserved",        0x0, 8),
	               XBitField("capabilityStation",         0x1, 1),
	               XBitField("capabilityModem",           0x0, 1),
	               XBitField("capabilityPhone",           0x0, 1),
	               XBitField("capabilityRouter",          0x0, 1),
	               XBitField("capabilityWAP",             0x0, 1),
	               XBitField("capabilityBridge",          0x0, 1),
	               XBitField("capabilityRepeater",        0x0, 1),
	               XBitField("capabilityOther",           0x0, 1),
	               XBitField("capabilityEnabledReserved", 0x0, 8),
	               XBitField("capabilityEnabledStation",  0x1, 1),
	               XBitField("capabilityEnabledModem",    0x0, 1),
	               XBitField("capabilityEnabledPhone",    0x0, 1),
	               XBitField("capabilityEnabledRouter",   0x0, 1),
	               XBitField("capabilityEnabledWAP",      0x0, 1),
	               XBitField("capabilityEnabledBridge",   0x0, 1),
	               XBitField("capabilityEnabledRepeater", 0x0, 1),
	               XBitField("capabilityEnabledOther",    0x0, 1),

	               XBitField("mgmtTlv", 0x8, 7),
	               XBitField("mgmtLength", 0xc, 9),
	               XBitField("mgmtAddressStringLength", 0x5, 8),
	               XBitField("mgmtAddressSubtype", 0x1, 8),
	               XBitField("mgmtAddressValue", mgmtAddressNumber, 32),
	               XBitField("mgmtInterfaceSubtype", 0x1, 8),
	               XBitField("mgmtInterfaceNumber", 0x0, 32),
	               XBitField("mgmtOidStringLength", 0x0, 8),
	              ]

class FaElement(Packet):
	name = "faElement "
	fields_desc = [XBitField("faElementTlv",        0x7f,                  7),
	               XBitField("faElementLength",     0x32,                  9),
	               XBitField("faElementOrgCode",    0x00040d,              24),
	               XBitField("faElementSubType",    0xb,                   8),
	               XBitField("faElementHmac",       0x0,                   256),
	               XBitField("faElementType",       elementType,           6),
	               XBitField("faElementState",      0x20,                  6),
	               XBitField("faElementMgmtVlan",   mgmtVlan,              12),
	               XBitField("faElementReserveved", 0x0,                   8),
	               XBitField("faElementSystemId",   deviceMacNumber << 32, 80),
	              ]

class LldpEnd(Packet):
	name = "lldpEnd "
	fields_desc = [XBitField("endTlv", 0x0, 7),
	               XBitField("endLength", 0x0, 9),
	              ]

# Make the base packet
generatedPacket = Ether(src=deviceMac, dst="01:80:c2:00:00:0e", type=0x88cc)/Lldp()/FaElement()

# Only add FA Element mappings if assignments exist
if(not assignmentMappings is None):
	class FaAssignment(Packet):
		name = "faAssignment "
		fields_desc = [XBitField("faAssignmentTlv", 0x7f, 7),
		               XBitField("faAssignmentLength", len(assignmentMappings) * 5 + 36, 9),
		               XBitField("faAssignmentOrgCode", 0x00040d, 24),
		               XBitField("faAssignmentSubType", 0xc, 8),
		               XBitField("faAssignmentHMAC", 0x0, 256),
		              ]

	class FaAssignmentMapping(Packet):
		name = "faAssignmentMapping "
		fields_desc = [XBitField("status", 0x1, 4),
		               XBitField("vlan", assignmentMappings[0][0], 12),
		               XBitField("isid", assignmentMappings[0][1], 24),
		              ]

	generatedPacket = generatedPacket/FaAssignment()

	for mapping in assignmentMappings:
		generatedPacket = generatedPacket/FaAssignmentMapping(vlan=mapping[0], isid=mapping[1])

# Don't forget the end of LLDPDU TLV
generatedPacket = generatedPacket/LldpEnd()


# The actual send loop
# Send once immediately...
sendp(generatedPacket, iface=interfaceName, verbose=False)
# Then send slightly faster than 4 times per ttl
while True:
	time.sleep(ttl / 4 - 1)
	sendp(generatedPacket, iface=interfaceName, verbose=False)
