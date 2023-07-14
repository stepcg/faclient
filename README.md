# FA Client
An LLDP Fabric Attach capable client for Linux, macOS, and Windows. Note: Windows usage requires the npcap driver be installed (if you use Wireshark, you probably already have this).

# Usage
Example command: faclient --assignmentMappings="(10:54320),(11:49920)" --elementType="FA_PROXY" --interfaceId="Eth1" --key="BeSureToDrinkYourOvaltine" --managementVlan=0 --ttl=120


Corresponding short options can be also used: --a="(10:54320),(11:49920)" --e="FA_PROXY" --i="Eth1" --k="BeSureToDrinkYourOvaltine" --m=0 --t=120

The only required field is interfaceName. assignmentMappings are optional additional VLAN requests, elementType will default to FA_PROXY/FA_PROXY_NOAUTH, authentication using a key is optional, managementVlan will default to 0 (untagged), and ttl will default to 120


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

interfaceId: The textual name of the network adapter to use.

key: The key to use for HMAC authentication. If not specificied, authentication will not be performed.

managementVLAN: The management VLAN 0-4095 to register the element with. Typically you want this to be 0 (untagged).

ttl: Time to live, 4-65535. Typically you want this to be 120 seconds. Too long and the entry may time out on the switch before being refreshed.
