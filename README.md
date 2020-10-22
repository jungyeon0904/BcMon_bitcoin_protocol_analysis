# BcMon_bitcoin_protocol_analysis
A wireshark dissector for the bitcoin protocol.

# Build instructions :
Linux
1. Clone this repository 
2. Move the lua file into ~/wireshark/<filename>.lua
3. Update ~/wireshark/init.lua
4. At the end of the init.lua file, specify the path to the <filename>.lua file 
as follows: dofile(“home/user/wireshark/<filename>.lua”)
5. Save init.lua and run wireshark.
