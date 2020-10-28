-- Create Sendcmpct protocol dissector
-- "SENDCMPCT" : Protocol name. Use at the Filter window.
-- "SENDCMPCT PROTOCOL" : Protocol Description to be displayed in the Packet detail, protocol column of list
sendcmpct_protocol = Proto("SENDCMPCT", "SENDCMPCT PROTOCOL")

-- Field Definition
local f = sendcmpct_protocol.fields

-- payload fields
f.bandwidth = ProtoField.uint8("sendcmpct.bandwidth", "Bandwidth", base.DEC)
f.version = ProtoField.uint8("sendcmpct.version", "Version", base.DEC)

-- SENDCMPCT dissector function 
function sendcmpct_protocol.dissector(buffer, pinfo, tree)
    -- validate packet length is adequate, otherwise quit
    --if buffer:len() > 9 then return end

    -- Add SubTree in the packet datail window
    local subtree = tree:add(sendcmpct_protocol, buffer(), "Sendcmpct message")

    --buffer first byte ~ 1byte add to field
    -- bandwidth mode name process
    local bandwidth_mode = buffer(0, 1)

    function get_bandwidth(bandwidth_mode)
        local bandwidth_name = "Unknown"

        if bandwidth_mode:uint() == 0 then
            bandwidth_name = "Low Bandwidth"
        else
            bandwidth_name = "High Bandwidth"
        end
        return bandwidth_name
    end
    
    local bandwidth_name = get_bandwidth(bandwidth_mode)
    subtree:add(f.bandwidth, buffer(0, 1)):append_text(" (" .. bandwidth_name .. ")")
    subtree:add(f.version, buffer(1, 1))
    
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

-- use the original dissector so we can still get to it
local bitcoin_table = DissectorTable.get("bitcoin.command")
 -- and take its place in the dissector table
 bitcoin_table:add("sendcmpct", sendcmpct_protocol)

