-- Create Sendcmpct protocol dissector
-- "SENDCMPCT" : Protocol name. Use at the Filter window.
-- "SENDCMPCT PROTOCOL" : Protocol Description to be displayed in the Packet detail, protocol column of list
sendcmpct_protocol = Proto("SENDCMPCT", "SENDCMPCT PROTOCOL")

-- Field Definition
local f = sendcmpct_protocol.fields

f.packetmagic = ProtoField.uint32("SENDCMPCT.pm", "Packet Magic", base.HEX)
f.commandname = ProtoField.string("SENDCMPCT.cn", "Command Name", base.ASCII)
f.payloadlength = ProtoField.uint32("SENDCMPCT.pl", "Payload Length", base.DEC)
f.payloadchecksum = ProtoField.uint32("SENDCMPCT.pc", "Payload Checksum", base.HEX)
f.bandwidth = ProtoField.string("SENDCMPCT.bw", "Bandwidth", base.ASCII)
-- f.bandwidth = ProtoField.uint8("SENDCMPCT.bw", "Bandwidth", base.DEC)
f.version = ProtoField.uint8("SENDCMPCT.ver", "Version", base.DEC)

-- SENDCMPCT dissector function 
function sendcmpct_protocol.dissector(buffer, pinfo, tree)
    -- validate packet length is adequate, otherwise quit
    if buffer:len() == 0 then return end

    -- Add SubTree in the packet datail window
    local subtree = tree:add(sendcmpct_protocol, buffer(), "Bitcoin protocol")

    --buffer first byte ~ 1byte add to field
    subtree:add(f.packetmagic, buffer(0, 4))
    subtree:add(f.commandname, buffer(4, 9)) --buffer(4, 12)
    subtree:add(f.payloadlength, buffer(16, 1)) -- allocate buffer is (16, 4) but little endian
    subtree:add(f.payloadchecksum, buffer(20, 4))
    if buffer(24,1):uint() == 0 then
        subtree:add(f.bandwidth, "Low Bandwidth")
    else
        subtreeLadd(f.bandwidth, "High Bandwidth")
    end
    -- subtree:add(f.bandwidth, buffer(24, 1))
    subtree:add(f.version, buffer(25, 1))
    
    -- set the protocol name
    local protocol_str = "Bitcoin";
    pinfo.cols.protocol = protocol_str
    -- set the info column name
    local info_str = "sendcmpct";
    pinfo.cols.info = info_str

end

--Initialization routine
function sendcmpct_protocol.init()
end

local tcp_dissector_table = DissectorTable.get("tcp.port")
-- save the original dissector so we can still get to it
original_http_dissector = tcp_dissector_table:get_dissector(8333)
tcp_dissector_table:add(8333, sendcmpct_protocol)

