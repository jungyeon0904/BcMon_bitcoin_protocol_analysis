# BcMon_bitcoin_protocol_analysis
New inv type and protocol messages that have been changed during block delivery due to Bitcoin Core version upgrade are not included in the Wireshark dissectors.
BcMon provides a Wireshark Bitcoin protocol analysis extension file.

Providing the bitcoin protocol extension file
: MSG_CMPCT_BLOCK == 4,sendcmpct, cmpctblock, getblocktxn, blocktxn

# Build instructions :
// Ubuntu 18.04, Wireshark 3.3.1

1. Clone this repository 
2. Move the lua file into ~/wireshark/<filename>.lua
3. Update ~/wireshark/init.lua
4. At the end of the init.lua file, specify the path to the <filename>.lua file 
as follows: dofile(“home/user/wireshark/<filename>.lua”)
5. Save init.lua and run wireshark.

# Bitcoin protocol status
<img src="https://user-images.githubusercontent.com/57450244/96885041-2958ec00-14bd-11eb-8653-e4b0dceed001.JPG" width="80%"></img>


