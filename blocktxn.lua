-- Create Sendcmpct protocol dissector
-- "SENDCMPCT" : Protocol name. Use at the Filter window.
-- "SENDCMPCT PROTOCOL" : Protocol Description to be displayed in the Packet detail, protocol column of list
blocktxn_protocol = Proto("BLOCKTXN", "BLOCKTXN PROTOCOL")

-- fixed variable
local N_SEQUENCE = 0xFFFFFFFF
local N_LOCK_TIME = 0x00000000

-- Field Definition
local f  = blocktxn_protocol.fields
-- Blocktxn payload fields
f.block_hash = ProtoField.bytes("blocktxn.block_hash", "Block Hash", base.NONE)
f.transactions_lengths = ProtoField.uint32("blocktxn.tx_len", "Transactions Lengths", base.DEC)
-- transactions = Raw Transaction + Serialization Transaction,

-- Raw Transaction payload fields
f.version = ProtoField.uint32("blocktxn.version", "Version", base.DEC)
f.tx_in_count = ProtoField.uint8("blocktxn.tx_in_count", "Tx Input Count", base.DEC)
-- f.tx_in field use Transaction In payload fields
f.tx_out_count = ProtoField.uint8("blocktxn.tx_out_count", "Tx Output Count", base.DEC)
-- f.tx_out field use Transaction Out payload fields
f.lock_time = ProtoField.uint32("blocktxn.lock_time", "Lock Time", base.HEX)

-- Serialization Transaction payload fields
f.marker = ProtoField.uint8("blocktxn.marker", "Marker", base.DEC)
f.flag = ProtoField.uint8("blocktxn.flag", "Flag", base.DEC)
f.script_witnesses = ProtoField.bytes("blocktxn.script_witnesses", "Script Witnesses", base.NONE)

-- Previous Output payload fields
f.previous_output = ProtoField.bytes("blocktxn.previous_output", "Previous Output", base.NONE) -- previous output hash data type is char[32] but chose uint to show ite easily.
f.index = ProtoField.uint32("blocktxn.index", "Index", base.HEX)

-- Transaction In payload fields
f.script_bytes = ProtoField.uint8("blocktxn.script_bytes", "Script Bytes", base.DEC)
f.script = ProtoField.bytes("blocktxn.script", "Script", base.NONE)
f.sequence = ProtoField.uint32("blocktxn.sequence", "Sequence", base.HEX)

-- Transaction Out payload fields
f.value = ProtoField.bytes("blocktxn.value", "Value", base.NONE)
f.pk_script_bytes = ProtoField.uint8("blocktxn.pk_script_bytes", "Pk Script Bytes", base.DEC)
f.pk_script = ProtoField.bytes("blocktxn.pk_script", "Pk Script", base.NONE)

-- BLOCKTXN dissector function 
function blocktxn_protocol.dissector(buffer, pinfo, tree)
    local maintree = tree:add(blocktxn_protocol, buffer(), "Blocktxn message")
    local offset = 0
    local len = buffer:len()

    -- dissection blocktxn payload fields
    maintree:add(f.block_hash, buffer(offset, 32))
    offset = offset + 32

    -- CompactSize uint Type Process
    function cmpctsize_uint(offset)
        local check_len = buffer(offset, 1)
        local cmpct_value = 0
        if check_len:uint() < 0xFD then
            return 1, offset -- basic encoding
        else
            offset = offset + 1
            return 2, offset -- little endian encoding
        end
    end


    local tx_len_point = 0 
    local tx_len_value = 0 -- cmpct_value data
    tx_len_point, offset = cmpctsize_uint(offset)

    if tx_len_point == 1 then -- uint()
        maintree:add(f.transactions_lengths, buffer(offset, tx_len_point))
        tx_len_value = buffer(offset, tx_len_point):uint()
    else
        maintree:add_le(f.transactions_lengths, buffer(offset, tx_len_point))
        tx_len_value = buffer(offset, tx_len_point):le_uint()
    end
    offset = offset + tx_len_point

    -- dissection blocktxn tree
    for i=1, tx_len_value, 1 do -- loop start point
        local subtree = maintree:add(blocktxn_protocol, buffer(), "Transaction Vector")

        subtree:add_le(f.version, buffer(offset, 4)) -- little_endian original 4byte but use 1byte
        offset = offset + 4

        -- Separation Raw tx version and New tx version
        local format_version = 0
        format_version = buffer(offset, 1) -- format_version separate tx version
   
        if format_version:uint() == 0x00 then -- exist marker field, marker field must be "Zero"
         subtree:add(f.marker, format_version)
            offset = offset + 1
            subtree:add(f.flag, buffer(offset, 1))
            offset = offset + 1
        end

        local tx_in_count_point = 0 
        local tx_in_count_value = 0
        tx_in_count_point, offset = cmpctsize_uint(offset)-- tx_in_count data type is compactsize uint

        if tx_in_count_point == 1 then -- uint()
            subtree:add(f.tx_in_count, buffer(offset, tx_in_count_point))
            tx_in_count_value = buffer(offset, tx_in_count_point):uint()
        else
            subtree:add_le(f.tx_in_count, buffer(offset, tx_in_count_point))
            tx_in_count_value = buffer(offset, tx_in_count_point):le_uint()
        end
        offset = offset + tx_in_count_point

        -- tx input process
        for i=1, tx_in_count_value, 1 do
            local inputtree = subtree:add(blocktxn_protocol, buffer(), "Transaction Input")
            inputtree:add(f.previous_output, buffer(offset, 32))
            offset = offset + 32
            inputtree:add(f.index, buffer(offset, 4))
            offset = offset + 4

            local script_point = 0
            local script_value = 0
            script_point, offset = cmpctsize_uint(offset)

            if script_point == 1 then -- uint()
                inputtree:add(f.script_bytes, buffer(offset, script_point))
                script_value = buffer(offset, script_point):uint()
            else
                inputtree:add_le(f.script_bytes, buffer(offset, script_point))
                script_value = buffer(offset, script_point):le_uint()
            end
            offset = offset + script_point

            inputtree:add(f.script, buffer(offset, script_value)) 
            offset = offset + script_value

            inputtree:add(f.sequence, buffer(offset, 4))
            offset = offset + 4
        end
    
        local tx_out_count_point = 0
        local tx_out_count_value = 0
        tx_out_count_point, offset = cmpctsize_uint(offset) -- tx_out_count data type is compactsize uint
        
        if tx_out_count_point == 1 then -- uint()
            subtree:add(f.tx_out_count, buffer(offset, tx_out_count_point))
            tx_out_count_value = buffer(offset, tx_out_count_point):uint()
        else
            subtree:add_le(f.tx_out_count, buffer(offset, tx_out_count_point))
            tx_out_count_value = buffer(offset, tx_out_count_point):le_uint()
        end
        offset = offset + tx_out_count_point

        -- tx out process
        for i=1, tx_out_count_value, 1 do
            local outputtree = subtree:add(blocktxn_protocol, buffer(), "Transaction Output")
            outputtree:add(f.value, buffer(offset, 8))
            offset = offset + 8
        
            local pk_script_point = 0
            local pk_script_value = 0
            pk_script_point, offset = cmpctsize_uint(offset)

            if pk_script_point == 1 then -- uint()
                outputtree:add(f.pk_script_bytes, buffer(offset, pk_script_point))
                pk_script_value = buffer(offset, pk_script_point):uint()
            else
                outputtree:add_le(f.pk_script_bytes, buffer(offset, pk_script_point))
                pk_script_value = buffer(offset, pk_script_point):le_uint()
            end
            offset = offset + pk_script_point

            outputtree:add(f.pk_script, buffer(offset, pk_script_value))
            offset = offset + pk_script_value
        end

        -- find script_witnesses bytes
        function script_witnesses_bytes(offset)
            local point = offset
            local endpoint = 0
            -- find Lock time 
            repeat
                point = point + 1
                endpoint = buffer(point, 4)
            until endpoint:uint() == N_LOCK_TIME -- == 0x00000000
            
            if (point + 4) == len then -- end of payload
                return point
            else -- check one more byte
                endpoint = buffer((point + 1), 4)
                if endpoint:uint() == N_LOCK_TIME then
                    point = point + 1
                    return point
                else
                    return point
                end
            end

        end


        if format_version:uint() == 0x00 then -- exist marker field, marker field must be "Zero"
            local point = script_witnesses_bytes(offset)
            subtree:add(f.script_witnesses, buffer(offset, (point - offset)) )
            offset = point
            subtree:add(f.lock_time, buffer(offset, 4))
            offset = offset + 4
        else
            subtree:add(f.lock_time, buffer(offset, 4))
            offset = offset + 4
        end

    end -- end point


    -- set the protocol name
    local protocol_str = "Bitcoin";
    pinfo.cols.protocol = protocol_str
    -- set the info column name
    local info_str = "blocktxn";
    pinfo.cols.info = info_str
    
end

function blocktxn_protocol.init()
end

-- use the original dissector so we can still get to it
local bitcoin_table = DissectorTable.get("bitcoin.command")
 -- and take its place in the dissector table
 bitcoin_table:add("blocktxn", blocktxn_protocol)
