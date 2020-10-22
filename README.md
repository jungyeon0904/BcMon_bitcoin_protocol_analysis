# BcMon_bitcoin_protocol_analysis
New protocol messages that have been changed during block delivery due to Bitcoin Core version upgrade are not included in the Wireshark dissectors.
BcMon provides a Wireshark Bitcoin protocol analysis extension file.

Providing the bitcoin protocol extension file
: sendcmpct, cmpctblock, getblocktxn, blocktxn

# Build instructions :
// Ubuntu 18.04, Wireshark 3.3.1

1. Clone this repository 
2. Move the lua file into ~/wireshark/<filename>.lua
3. Update ~/wireshark/init.lua
4. At the end of the init.lua file, specify the path to the <filename>.lua file 
as follows: dofile(“home/user/wireshark/<filename>.lua”)
5. Save init.lua and run wireshark.

# Bitcoin protocol status
<img src="https://user-images.githubusercontent.com/57450244/96884182-2e696b80-14bc-11eb-8699-15d83f751ab7.JPG" width="90%"></img>
