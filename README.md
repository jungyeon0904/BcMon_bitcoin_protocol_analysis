# BcMon_bitcoin_protocol_analysis
New inv type and protocol messages that have been changed during block delivery due to Bitcoin Core version upgrade are not included in the Wireshark dissectors.
BcMon provides a Wireshark Bitcoin protocol analysis extension file.


Providing the bitcoin protocol dissector files  
: sendcmpct, cmpctblock, getblocktxn, blocktxn


# How To Run This Script
// Ubuntu 18.04, Wireshark 3.3.1


See the Wireshark Developer's Guide chapter on Lua  
(https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html).


1. Clone this repository 
2. Move the lua file into Wireshark's global configuration directory  
   (Window: C:\Program Files\Wireshark, Linux: /usr/share/wireshark)
3. At the end of the init.lua file located in the Wireshark's global configuration directory,  
   specify the path to the \<filename>.lua file as follows: **dofile(DATA_DIR.."\<filename>.lua”)**
4. Save init.lua and run wireshark
5. On the Enabled Protocols tab of the Analysis menu, set to Enable Protocols.  

<img src="https://user-images.githubusercontent.com/57450244/121110786-d31c9b80-c848-11eb-9506-bfc5de5055b5.gif" width="500" height="400"></img>







# Bitcoin Compact Block Relay Protocol

The protocol is intended to be used in two ways, depending on the peers and bandwidth available, as shown in the figure.  

<img src="https://user-images.githubusercontent.com/57450244/121130893-ff94df80-c869-11eb-896f-832337cd71a5.jpg" width="500" height="300">



Sendcmpct
---------
<img src="https://user-images.githubusercontent.com/57450244/121138358-91084f80-c872-11eb-9adf-60faad521376.png" width="600" height="500"></img>

Cmpctblock
----------
<img src="https://user-images.githubusercontent.com/57450244/121138365-92397c80-c872-11eb-844b-f2b69815582f.png" width="600" height="500"></img>

Getblocktxn
----------
<img src="https://user-images.githubusercontent.com/57450244/121138367-92d21300-c872-11eb-8efd-f4e1eb5aa24a.png" width="600" height="500"></img>

Blocktxn 
--------
<img src="https://user-images.githubusercontent.com/57450244/121138369-936aa980-c872-11eb-97eb-c34b02e6decb.png" width="600" height="500"></img>

Reference
---------
https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki and https://en.bitcoin.it/wiki/Protocol_documentation
