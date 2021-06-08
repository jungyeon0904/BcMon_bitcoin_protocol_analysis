# BcMon_bitcoin_protocol_analysis
New inv type and protocol messages that have been changed during block delivery due to Bitcoin Core version upgrade are not included in the Wireshark dissectors.
BcMon provides a Wireshark Bitcoin protocol analysis extension file.


Providing the bitcoin protocol extension file
: sendcmpct, cmpctblock, getblocktxn, blocktxn


# How To Run This Script
// Ubuntu 18.04, Wireshark 3.3.1


See the Wireshark Developer's Guide chapter on Lua
(https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html).


1. Clone this repository 
2. Move the lua file into Wireshark's global configuration directory
3. At the end of the init.lua file located in the Wireshark's global configuration directory, 


   specify the path to the \<filename>.lua file as follows: **dofile(DATA_DIR.."\<filename>.lua”)**
4. Save init.lua and run wireshark
5. On the Enabled Protocols tab of the Analysis menu, set to Enable Protocols.

<img src="https://user-images.githubusercontent.com/57450244/121110786-d31c9b80-c848-11eb-9506-bfc5de5055b5.gif" width="500" height="400">







# Bitcoin Compact Block Relay Protocol

The protocol is intended to be used in two ways, depending on the peers and bandwidth available, as shown in the figure.

Sendcmpct
---------


Cmpctblock
----------


Getblocktxn
----------


Blocktxn 
--------

