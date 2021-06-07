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

   specify the path to the <\filename>.lua file as follows: **dofile(DATA_DIR.."filename.lua”)**
4. Save init.lua and run wireshark

   
   
# Wireshark Bitcoin protocol status
<img src="https://user-images.githubusercontent.com/57450244/96885041-2958ec00-14bd-11eb-8653-e4b0dceed001.JPG" width="70%"></img>


# getdata packet // ERROR

<img src="https://user-images.githubusercontent.com/57450244/96888036-290e2000-14c0-11eb-8ab9-3aea6e95a1d0.JPG" width="70%"></img>

"MSG_CMPCT_BLOCK" inventory type field marked "Unknown (error)"

The object type is currently defined as one of the following possibilities:

<img src="https://user-images.githubusercontent.com/57450244/96888060-2e6b6a80-14c0-11eb-8d88-740c09dbc001.JPG" width="70%"></img>


# sendcmpct packet // ERROR

<img src="https://user-images.githubusercontent.com/57450244/96888152-47741b80-14c0-11eb-9f26-76931756472b.JPG" width="70%"></img>


# sendcmpct packet // Analysis

<img src="https://user-images.githubusercontent.com/57450244/96888173-4cd16600-14c0-11eb-8d6e-def8eef3ead5.JPG" width="70%"></img>


# cmpctblock // ERROR

<img src="https://user-images.githubusercontent.com/57450244/96888201-52c74700-14c0-11eb-8014-694f11b46380.JPG" width="70%"></img>


# getblocktxn // ERROR

<img src="https://user-images.githubusercontent.com/57450244/96888218-578bfb00-14c0-11eb-8a8a-189706a72236.JPG" width="70%"></img>
