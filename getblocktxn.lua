-- Create Sendcmpct protocol dissector
-- "GETBLOCKTXN" : Protocol name. Use at the Filter window.
-- "GETBLOCKTXN PROTOCOL" : Protocol Description to be displayed in the Packet detail, protocol column of list
getblocktxn_protocol = Proto("GETBLOCKTXN", "GETBLOCKTXN PROTOCOL")

-- Field Definition
local f  = getblocktxn_protocol.fields
-- Blocktxn payload fields
f.block_hash = ProtoField.bytes("getblocktxn.block_hash", "Block Hash", base.NONE)
f.indexes_length = ProtoField.uint8("getblocktxn.indexes_length", "Indexes Length", base.DEC) -- CmpctSize 1 or 3 byte
f.indexes = ProtoField.uint8("getblocktxn.indexes", "Indexes", base.DEC) -- 1 or 3 byte * indexes_length, Differentially encoded

local index_len = 0
local index_value = 0
local previous_index = 0 -- previous index value
local present_index = 0 -- present index value
local check_len = 0

-- GETBLOCKTXN dissector function 
function getblocktxn_protocol.dissector(buffer, pinfo, tree)
    local maintree = tree:add(getblocktxn_protocol, buffer(), "Getblocktxn message")
    local offset = 0
    local len = buffer:len()

    -- CompactSize uint Type Process
    function cmpctsize_uint(offset)
        check_len = buffer(offset, 1):uint()
        if check_len < 0xFD then
            return 1, offset -- basic encoding
        else
            offset = offset + 1
            return 2, offset -- little endian encoding
        end
    end

    maintree:add(f.block_hash, buffer(offset, 32))
    offset = offset + 32

    index_len = 0 -- index length

    index_len, offset = cmpctsize_uint(offset)
    -- dissection 1 byte and 3 byte
    if index_len == 1 then -- :uint()
        maintree:add(f.indexes_length, buffer(offset, index_len))
    else
        maintree:add_le(f.indexes_length, buffer(offset, index_len))
    end
    offset = offset + index_len

    -- dissection Indexes
    local subtree = maintree:add(getblocktxn_protocol, buffer(), "Indexes message") --Indexes message
    
    -- previous & present index position
    index_value = 0
    
    -- first index byte
    
    index_value, offset = cmpctsize_uint(offset)
    if index_value == 1 then -- uint()
        subtree:add(f.indexes, buffer(offset, index_value))
        previous_index = buffer(offset, index_value):uint()
    else
        subtree:add_le(f.indexes, buffer(offset, index_value))
        previous_index = buffer(offset, index_value):le_uint()
    end
    offset = offset + index_value

    -- other index bytes
    if offset ~= len then
        repeat
            index_value = 0
            index_value, offset = cmpctsize_uint(offset)
            
            -- dissection 1 byte and 3 byte
            if index_value == 1 then -- uint()
                present_index = ((buffer(offset, index_value):uint()) + previous_index + 1)
                subtree:add(f.indexes, buffer(offset, index_value), present_index)
            else
                present_index = ((buffer(offset, index_value):le_uint()) + previous_index + 1)
                subtree:add(f.indexes, buffer(offset, index_value), present_index)
            end
            
            previous_index = present_index
            offset = offset + index_value

        until offset == len
    end
    
    -- set the protocol name
    local protocol_str = "Bitcoin";
    pinfo.cols.protocol = protocol_str
    -- set the info column name
    local info_str = "getblocktxn";
    pinfo.cols.info = info_str
end


--Initialization routine
function getblocktxn_protocol.init()
end

-- use the original dissector so we can still get to it
local bitcoin_table = DissectorTable.get("bitcoin.command")
 -- and take its place in the dissector table
 bitcoin_table:add("getblocktxn", getblocktxn_protocol)
