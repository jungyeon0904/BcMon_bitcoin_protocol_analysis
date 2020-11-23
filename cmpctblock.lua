-- Create Sendcmpct protocol dissector
-- "GETBLOCKTXN" : Protocol name. Use at the Filter window.
-- "GETBLOCKTXN PROTOCOL" : Protocol Description to be displayed in the Packet detail, protocol column of list
cmpctblock_protocol = Proto("CMPCTBLOCK", "CMPCTBLOCK PROTOCOL")

-- Field Definition
local f  = cmpctblock_protocol.fields
-- Blocktxn payload fields
f.block_hash = ProtoField.bytes("cmpctblock.block_hash", "Block Hash", base.NONE)
f.nonce = ProtoField.uint64("cmpctblock.nonce", "Nonce", base.HEX) 
f.shortids_length = ProtoField.uint8("cmpctblock.shortids_length", "Shortids Length", base.DEC) -- 1 or 3 byte , CompactSize
f.shortids = ProtoField.bytes("cmpctblock.shortids", "Shortids", base.NONE)
f.prefilledtxn_length = ProtoField.uint8("cmpctblock.prefilledtxn_length", "Prefilledtxn Length", base.DEC) -- 1 or 3 byte , CompactSize
f.prefilledtxn_index = ProtoField.uint8("cmpctblock.prefilledtxn_index", "Prefilledtxn Index", base.DEC) -- 1 or 3 byte , CompactSize
-- prefilledtxn
f.block_hash = ProtoField.bytes("cmpctblock.block_hash", "Block Hash", base.NONE)
f.transactions_lengths = ProtoField.uint32("cmpctblock.tx_len", "Transactions Lengths", base.DEC)
-- transactions = Raw Transaction + Serialization Transaction,

-- Raw Transaction payload fields
f.version = ProtoField.uint32("cmpctblock.version", "Version", base.DEC)
f.tx_in_count = ProtoField.uint8("cmpctblock.tx_in_count", "Tx Input Count", base.DEC)
-- f.tx_in field use Transaction In payload fields
f.tx_out_count = ProtoField.uint8("cmpctblock.tx_out_count", "Tx Output Count", base.DEC)
-- f.tx_out field use Transaction Out payload fields
f.lock_time = ProtoField.uint32("cmpctblock.lock_time", "Lock Time", base.HEX)

-- Serialization Transaction payload fields
f.marker = ProtoField.uint8("cmpctblock.marker", "Marker", base.DEC)
f.flag = ProtoField.uint8("cmpctblock.flag", "Flag", base.DEC)
f.script_witnesses = ProtoField.bytes("cmpctblock.script_witnesses", "Script Witnesses", base.NONE)

-- Previous Output payload fields
f.previous_output = ProtoField.bytes("cmpctblock.previous_output", "Previous Output", base.NONE) -- previous output hash data type is char[32] but chose uint to show ite easily.
f.index = ProtoField.uint32("cmpctblock.index", "Index", base.HEX)

-- Transaction In payload fields
f.script_bytes = ProtoField.uint8("cmpctblock.script_bytes", "Script Bytes", base.DEC) -- 1 or 3 byte , CompactSize
f.script = ProtoField.bytes("cmpctblock.script", "Script", base.NONE)
f.sequence = ProtoField.uint32("cmpctblock.sequence", "Sequence", base.HEX)

-- Transaction Out payload fields
f.value = ProtoField.bytes("cmpctblock.value", "Value", base.NONE)
f.pk_script_bytes = ProtoField.uint8("cmpctblock.pk_script_bytes", "Pk Script Bytes", base.DEC) -- 1 or 3 byte , CompactSize
f.pk_script = ProtoField.bytes("cmpctblock.pk_script", "Pk Script", base.NONE)

local N_SEQUENCE = 0xFFFFFFFF
local N_LOCK_TIME = 0x00000000
local endpoint = 0

-- CMPCTBLOCK dissector function 
function cmpctblock_protocol.dissector(buffer, pinfo, tree)
    local maintree = tree:add(cmpctblock_protocol, buffer(), "Cmpctblock message")
    local offset = 0
    local len = buffer:len()

    maintree:add(f.block_hash, buffer(offset, 80)) -- fix 80 byte 
    offset = offset + 80

    maintree:add(f.nonce, buffer(offset, 8)) -- fix 8 byte
    offset = offset + 8

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

    local shrtid_point = 0
    local shrtid_value = 0
    shrtid_point, offset = cmpctsize_uint(offset)

    if shrtid_point == 1 then -- uint()
        maintree:add(f.shortids_length, buffer(offset, shrtid_point))
        shrtid_value = buffer(offset, shrtid_point):uint()
    else
        maintree:add_le(f.shortids_length, buffer(offset, shrtid_point))
        shrtid_value = buffer(offset, shrtid_point):le_uint()
    end
    offset = offset + shrtid_point
    shrtid_value = offset + (shrtid_value * 6)

    local subtree = maintree:add(cmpctblock_protocol, buffer(), "Shortids message")
    repeat
        subtree:add(f.shortids, buffer(offset, 6)) -- fix 6 byte
        offset = offset + 6
    until offset == shrtid_value

    local prefilledtxn_point = 0
    local prefilledtxn_value = 0
    prefilledtxn_point, offset = cmpctsize_uint(offset)

    if prefilledtxn_point == 1 then -- uint()
        maintree:add(f.prefilledtxn_length, buffer(offset, prefilledtxn_point))
        prefilledtxn_value = buffer(offset, prefilledtxn_point):uint()
    else
        maintree:add_le(f.prefilledtxn_length, buffer(offset, prefilledtxn_point))
        prefilledtxn_value = buffer(offset, prefilledtxn_point):le_uint()
    end
    offset = offset + prefilledtxn_point

    -- dissection prefilled transactions(== tx, witd)
    for i=1, prefilledtxn_value, 1 do
        local pretxtree = maintree:add(cmpctblock_protocol, buffer(), "Prefilled Transaction message")
        local pretx_index_point = 0
        pretx_index_point, offset = cmpctsize_uint(offset)

        if pretx_index_point == 1 then -- uint()
            pretxtree:add(f.prefilledtxn_index, buffer(offset, pretx_index_point))
        else
            pretxtree:add_le(f.prefilledtxn_index, buffer(offset, pretx_index_point))
        end
        offset = offset + pretx_index_point

        pretxtree:add_le(f.version, buffer(offset, 4)) -- little_endian original 4byte but use 1byte
        offset = offset + 4

        -- Separation Raw tx version and New tx version
        local format_version = 0
        format_version = buffer(offset, 1) -- format_version separate tx version
   
        if format_version:uint() == 0x00 then -- exist marker field, marker field must be "Zero"
            pretxtree:add(f.marker, format_version)
            offset = offset + 1
            pretxtree:add(f.flag, buffer(offset, 1))
            offset = offset + 1
        end

        -- tx in
        local tx_in_point = 0
        local tx_in_value = 0
        tx_in_point, offset = cmpctsize_uint(offset)

        if tx_in_point == 1 then -- uint()
            pretxtree:add(f.tx_in_count, buffer(offset, tx_in_point))
            tx_in_value = buffer(offset, tx_in_point):uint()
        else
            pretxtree:add_le(f.tx_in_count, buffer(offset, tx_in_point))
            tx_in_value = buffer(offset, tx_in_point):le_uint()
        end
        offset = offset + tx_in_point
        
        for i=1, tx_in_value, 1 do
            local inputtree = pretxtree:add(cmpctblock_protocol, buffer(), "Prefilled Transaction Input")
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

            inputtree:add(f.sequence, buffer(offset, 4)) -- fix 4 byte
            offset = offset + 4
        end

        -- tx out
        local tx_out_point = 0
        local tx_out_value = 0
        tx_out_point, offset = cmpctsize_uint(offset)

        if tx_out_point == 1 then -- uint()
            pretxtree:add(f.tx_out_count, buffer(offset, tx_out_point))
            tx_out_value = buffer(offset, tx_out_point):uint()
        else
            pretxtree:add_le(f.tx_out_count, buffer(offset, tx_out_point))
            tx_out_value = buffer(offset, tx_out_point):le_uint()
        end
        offset = offset + tx_out_point
        
        for i=1, tx_out_value, 1 do
            local outputtree = pretxtree:add(cmpctblock_protocol, buffer(), "Prefilled Transaction Output")
            outputtree:add(f.value, buffer(offset, 8))
            offset = offset + 8
        
            local pk_script_point = 0
            local pk_script_value = 0
            pk_script_point, offset = cmpctsize_uint(offset)
            
            if pk_script_point == 1 then -- uint()
                outputtree:add(f.script_bytes, buffer(offset, pk_script_point))
                pk_script_value = buffer(offset, pk_script_point):uint()
            else
                outputtree:add_le(f.script_bytes, buffer(offset, pk_script_point))
                pk_script_value = buffer(offset, pk_script_point):le_uint()
            end
            offset = offset + pk_script_point

            outputtree:add(f.pk_script, buffer(offset, pk_script_value))
            offset = offset + pk_script_value
        end

        -- find script_witnesses bytes
        function script_witnesses_bytes(offset)
            local point = offset
            --endpoint
            -- find Lock time 
            repeat
                point = point + 1
                endpoint = buffer(point, 4):uint()
            until endpoint == N_LOCK_TIME -- == 0x00000000
            
            if (point + 4) == len then -- end of payload
                return point
            else -- check one more byte
                endpoint = buffer((point + 1), 4)
                if endpoint == N_LOCK_TIME then
                    point = point + 1
                    return point
                else
                    return point
                end
            end

        end


        if format_version:uint() == 0x00 then -- exist marker field, marker field must be "Zero"
            --local point = script_witnesses_bytes(offset)
            --pretxtree:add(f.script_witnesses, buffer(offset, (point - offset)) )
            --offset = point
            pretxtree:add(f.script_witnesses, buffer(offset, 34))
            offset = offset + 34
            pretxtree:add(f.lock_time, buffer(offset, 4))
            offset = offset + 4
        else
            pretxtree:add(f.lock_time, buffer(offset, 4))
            offset = offset + 4
        end

    end

    -- set the protocol name
    local protocol_str = "Bitcoin";
    pinfo.cols.protocol = protocol_str
    -- set the info column name
    local info_str = "cmpckblock";
    pinfo.cols.info = info_str
end

--Initialization routine
function cmpctblock_protocol.init()
end

-- use the original dissector so we can still get to it
local bitcoin_table = DissectorTable.get("bitcoin.command")
 -- and take its place in the dissector table
 bitcoin_table:add("cmpctblock", cmpctblock_protocol)