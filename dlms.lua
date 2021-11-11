--
-- Lua dissector for DLMS/COSEM
-- Version 1.0
-- Last update: 28th March 2018
--
-- Developed as a part of IRONSTONE research project
-- 
-- (c) Petr Matousek, FIT BUT, Czech Republic, 2018
-- Contact:  matousp@fit.vutbr.cz
--
-- This is not a full DLMS dissector: it parses only selected DLMS/COSEM messages
-- LN referencing support only
--

-- All dissectors have a Proto object (table)
--   the fields are name and description.
-- declare the protocol
dlms_proto = Proto("DLMS","DLMS/COSEM")

-- the only data structure in lua is a table: an associative array, so 0x60 -> "AARQ ...."
-- declare the value strings
local COSEMpdu = {
   [0x60] = "AARQ Association Request",
   [0x61] = "AARE Association Response",
   [0x62] = "AARL Release Request",
   [0x63] = "AARE Release Response",
   [0x64] = "ABRT Abort",
   [0xc0] = "GetRequest",
   [0xc1] = "SetRequest",
   [0xc2] = "EventNotificationRequest",
   [0xc3] = "ActionRequest",
   [0xc4] = "GetResponse",
   [0xc5] = "SetResponse",
   [0xc7] = "ActionResponse"
}

local GetRequestVALS = {
   [1] = "GetRequestNormal",
   [2] = "GetRequestNext",
   [3] = "GetRequestWithList"
} 

local GetResponseVALS = {
   [1] = "GetResponseNormal",
   [2] = "GetResponseWithDatablock",
   [3] = "GetResponseWithList"
}

local SetRequestVALS = {
   [1] = "SetRequestNormal",
   [2] = "SetRequestWithFirstDatablock",
   [3] = "SetRequestWithDatablock",
   [4] = "SetRequestWithList",
   [5] = "SetRequestWithListAndFirstDatablock"
}

local SetResponseVALS = {
   [1] = "SetResponseNormal",
   [2] = "SetResponseWithFirstDatablock",
   [3] = "SetResponseWithDatablock",
   [4] = "SetResponseWithList",
   [5] = "SetResponseWithListAndFirstDatablock"
}

local GetDataTypeVALS = { 
   [0] = "null-data",
   [1] = "array",
   [2] = "structure",
   [3] = "boolean",
   [4] = "bit-string",
   [5] = "double-long",
   [6] = "double-long-unsigned",
   [9] = "octet-string",
   [10] = "visible-string",
   [13] = "bcd",
   [15] = "integer",
   [16] = "long",
   [17] = "unsigned",
   [18] = "long-unsigned",
   [19] = "compact-array",
   [20] = "long64",
   [21] = "long64-unsigned",
   [22] = "enum",
   [23] = "float32",
   [24] = "float64",
   [25] = "date_time",
   [26] = "data",
   [27] = "time",
   [255] = "do-not-care"
}

local GetDataResultVALS = {
   [0] = "data",
   [1] = "data-access-result"
}

local DataBlockResultVALS = {
   [0] = "raw-data",
   [1] = "data-access-result"
}

local BooleanVALS = {
   [0] = "False",
   [1] = "True"
}

local DataAccessResultVALS = {
   [0] = "Success",
   [1] = "HardwareFault",
   [2] = "TemporaryFailure",
   [3] = "ReadWriteDenied",
   [4] = "ObjectUndefined",
   [9] = "ObjectClassInconsistent",
   [11] = "ObjectUnavailable",
   [12] = "TypeUnmatched",
   [13] = "ScopeOfAccessViolated",
   [14] = "DataBlockUnavailable",
   [15] = "LongGetAborted",
   [16] = "NoLongGetInProgress",
   [17] = "LongSetAborted",
   [18] = "NoLongSetInProgress",
   [250] = "OtherReason"
}

local ContextVALS = {   -- AARQ: last two bytes of the application context name (OID)
   [0x0101] = "LN Referencing, Without Ciphering",
   [0x0102] = "SN Referencing, Without Ciphering",
   [0x0103] = "LN Referencing, With Ciphering",
   [0x0104] = "SN Referencing, With Ciphering",
   [0x0200] = "Lowest Level Security",
   [0x0201] = "Low Level Security",
   [0x0202] = "High Level Security", 
   [0x0203] = "High Level Security - MD5", 
   [0x0204] = "High Level Security - SHA1", 
   [0x0205] = "High Level Security - GMAC"
}

local ACSErequirementsVALS = {
   [0] = "authentication",
   [1] = "application-context-negotiation",
   [2] = "higher-level-assocation",
   [3] = "nested-assocation"
}

local AssociationResultVALS = {
   [0] = "accepted",
   [1] = "rejected-permanent",
   [2] = "rejected-transient",
}

local ASCEserviceUserVALS = {
   [0] = "null",
   [1] = "no-reason-given",
   [2] = "application-context-name-not-support",
   [11] = "authentication-mechanism-name-not-recognized",
   [12] = "authentication-mechanism-name-required",
   [13] = "authentication-failure",
   [14] = "authentication-required"
}

local ASCEserviceUserVALS = {
   [0] = "null",
   [1] = "no-reason-given",
   [2] = "application-context-name-not-support",
   [11] = "authentication-mechanism-name-not-recognized",
   [12] = "authentication-mechanism-name-required",
   [13] = "authentication-failure",
   [14] = "authentication-required"
}

local ASCEserviceProviderVALS = {
   [0] = "null",
   [1] = "no-reason-given",
   [2] = "no-common-acse-version",
}

-- Declare the Wireshark fields

-- fields in the dissector are created using ProtoField objects.  Params: name, abbv, type, valuestring

-- DLMS header
local APDU_type = ProtoField.uint8("dlms.apdu_type","Type",base.HEX,COSEMpdu)

-- DLMS GetRequest and SetRequest fields
local GetRequest = ProtoField.uint8("dlms.GetRequest","GetRequest",base.HEX,GetRequestVALS)
local SetRequest = ProtoField.uint8("dlms.SetRequest","SetRequest",base.HEX,SetRequestVALS)
local Request_invoke_id = ProtoField.uint8("dlms.request_invoke_id","Invoke ID and Priority",base.HEX)
local Class_id = ProtoField.uint16("dlms.class_id","class-id")
local Instance_id = ProtoField.string("dlms.instance_id","OBIS code")
local Attribute_id = ProtoField.uint8("dlms.attribute_id","attribute-id")
local Access_selection = ProtoField.uint8("dlms.access_selection","access-selection")
local Block_number = ProtoField.uint32("dlms.block_number","Block number",base.HEX)

-- DLMS GetResponseNormal
local GetResponse = ProtoField.uint8("dlms.GetResponse","GetResponse",base.HEX,GetResponseVALS)
local SetResponse = ProtoField.uint8("dlms.SetResponse","SetResponse",base.HEX,SetResponseVALS)
local Response_invoke_id = ProtoField.uint8("dlms.response_invoke_id","Invoke ID and Priority",base.HEX)
local Response_result = ProtoField.bytes("dlms.response_result","Data",base.DOT)
local Response_getData = ProtoField.uint8("dlms.response_getData","GetDataResult",base.DEC,GetDataResultVALS)
local DataType = ProtoField.uint8("dlms.dataType","Data type",base.DEC,GetDataTypeVALS)
local DataStringLen = ProtoField.uint8("dlms.dataStringLen","Length",base.DEC)

-- GetResponse Value Types
local StringValue = ProtoField.bytes("dlms.StringValue","Value",base.DOT)
local LongValue = ProtoField.uint16("dlms.LongValue","Value",base.DEC)
local BooleanValue = ProtoField.uint8("dlms.BooleanValue","Value",base.DEC, BooleanVALS)
local IntegerValue = ProtoField.uint8("dlms.IntegerValue","Value",base.DEC)
local DoubleLongValue = ProtoField.uint32("dlms.IntegerValue","Value",base.DEC)
local Long64Value = ProtoField.uint64("dlms.long64","Value",base.DEC)

-- GetResponseWithDataBlock
local LastBlock = ProtoField.uint8("dlms.lastBlock","Last block",base.DEC, BooleanVALS)
local BlockNumber = ProtoField.uint32("dlms.blockNumber", "Block number",base.DEC)
local DataBlockResult = ProtoField.uint8("dlms.dataBlockResult","Result",base.DEC, DataBlockResultVALS)
local DataAccessResult = ProtoField.uint8("dlms.dataAccessResult","DataAccessResult",base.DEC, DataAccessResultVALS)

-- Assign all the fields to the Protocol in order.
dlms_proto.fields = {DLMS, APDU_type, GetRequest, SetRequest, Request_invoke_id, Class_id, Instance_id, Attribute_id, Access_selection, Block_number, GetResponse, SetResponse, Response_invoke_id, Response_result, Response_getData, DataType, DataStringLen, StringValue, LongValue, BooleanValue, IntegerValue, DoubleLongValue, Long64Value, LastBlock, BlockNumber, DataBlockResult, DataAccessResult}

-- The dissector function is a "member" of the Proto object.
-- buffer : the buffer to use (a tvb object). -- https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb
-- pinfo : the packet info (has a bunch of fields -- see the docs: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html#lua_class_Pinfo
-- tree : the tree on which to add the packet items.
--
-- create the dissection function
function dlms_proto.dissector(buffer, pinfo, tree)

    -- Set the protocol column
    -- add -> Big Endian
   local t_dlms = tree:add(dlms_proto, buffer())
   local offset = 0
   local frame_len = 0

   -- BYTE[0] is a uint: message type.
   local dlms_type = buffer(offset,1):uint()

    -- create the DLMS protocol tree item
    t_dlms:add(APDU_type, buffer(offset,1))
    frame_len = buffer:len()

    -- make a column available for display; reach into the COSEMpdu object and get the string.
    pinfo.cols['info'] = "DLMS "..COSEMpdu[dlms_type]

    if dlms_type == 0xc0 then
        -- processing DLMS.GetRequest
        -- BYTE[1] is a uint: the Request Type { 1 or 2 }
        local getRequestType = buffer(offset+1,1):uint()
        t_dlms:add(GetRequest, buffer(offset+1,1))

        if getRequestType == 1 then 
            -- getRequestNormal
            -- BYTE[2]: request revoke id.
            t_dlms:add(Request_invoke_id, buffer(offset+2,1))

            -- BYTE[3,end]:
            local t_Descriptor = t_dlms:add(buffer(offset+3),"Cosem-Attribute-Descriptor")

            -- important components of the Cosem-Attribute-Descriptor
            -- WORD [3,5) : class
            local class        = buffer(offset+3,2):uint()
            -- BYTES[5,11) : each byte is a part of the OBIS identifer.
            local instance     = buffer(offset+5,6)
            local obis         = string.format("%d.%d.%d.%d.%d.%d",instance(0,1):uint(),instance(1,1):uint(),instance(2,1):uint(),instance(3,1):uint(),instance(4,1):uint(),instance(5,1):uint())
            -- BYTE[11]: attribute
            local attribute    = buffer(offset+11,1):uint()

            t_Descriptor:add(Class_id, buffer(offset+3,2))
            t_Descriptor:add(Instance_id, buffer(offset+5,6),obis)
            t_Descriptor:add(Attribute_id, buffer(offset+11,1))

            -- BYTE[12] : access selection.
            t_dlms:add(Access_selection, buffer(offset+12,1))
            pinfo.cols['info'] = GetRequestVALS[getRequestType]..", class="..class..", OBIS="..obis..", attr="..attribute

        elseif getRequestType == 2 then 
            -- getRequestNext
            -- BYTE[2] : request revoke id
            t_dlms:add(Request_invoke_id, buffer(offset+2,1))
            -- BYTES[3,7) : block number
            t_dlms:add(Block_number, buffer(offset+3,4))
            local block_number = buffer(offset+3,4):uint()

            pinfo.cols['info'] = GetRequestVALS[getRequestType]..", block no: "..block_number

        else
            -- UNKNOWN?  UNEXPECTED?
            pinfo.cols['info'] = GetRequestVALS[getRequestType]
        end
    end

    if dlms_type == 0xc1 then
        -- processing DLMS.SetRequest
        -- BYTE[1] is a uint: the Request Type { 1 or 2 }
        local setRequestType = buffer(offset+1,1):uint()
        t_dlms:add(SetRequest,buffer(offset+1,1))

        if setRequestType == 1 then 
            -- setRequestNormal
            -- BYTE[2]: request revoke id.
            t_dlms:add(Request_invoke_id,buffer(offset+2,1))
            -- Same as getRequestType
            local t_Descriptor = t_dlms:add(buffer(offset+3),"Cosem-Attribute-Descriptor")
            local class = buffer(offset+3,2):uint()
            local instance = buffer(offset+5,6)
            local obis = string.format("%d.%d.%d.%d.%d.%d",instance(0,1):uint(),instance(1,1):uint(),instance(2,1):uint(),instance(3,1):uint(),instance(4,1):uint(),instance(5,1):uint())
            local attribute = buffer(offset+11,1):uint()

            t_Descriptor:add(Class_id, buffer(offset+3,2))
            t_Descriptor:add(Instance_id, buffer(offset+5,6),obis)
            t_Descriptor:add(Attribute_id, buffer(offset+11,1))

            t_dlms:add(Access_selection, buffer(offset+12,1))

            -- offset hard advance.
            offset = offset + 13
            -- the rest of the packet.
            local dataLen = frame_len - 13

            -- BYTES[13,end] : data
            local t_data = t_dlms:add(buffer(offset,dataLen),"Data")

            -- BYTE[13] : data type index.
            local dataTypeIndex = buffer(offset,1):uint()
            local value
            t_data:add(DataType,buffer(offset,1))

            -- processing long integer or long unsigned (16 bits)
            if dataTypeIndex == 16 or dataTypeIndex == 18 then 
                -- BYTES[14,end] : long
                t_data:add(LongValue,buffer(offset+1,dataLen-1))
                value = buffer(offset+1,dataLen-1):uint()
            end

            -- processing Boolean (8 bits)
            if dataTypeIndex == 3 then
                -- BYTES[14,end] : boolean
                t_data:add(BooleanValue, buffer(offset+1,dataLen-1))
                value = buffer(offset+1,dataLen-1):uint()
            end

            -- processing double long and double long unsigned (32 bits)
            if dataTypeIndex == 5 or dataTypeIndex == 6 then
                -- BYTES[14,end] : double long
                t_data:add(DoubleLongValue, buffer(offset+1,dataLen-1))
                value = buffer(offset+1,dataLen-1):uint()
            end

            -- processing structure and array (sequence of data)
            if dataTypeIndex == 1 or dataTypeIndex == 2 then
                -- BYTES[14,end] : string / byte array
                t_data:add(StringValue,buffer(offset+1,dataLen-1))
                value = buffer(offset+1,dataLen-1):uint()
            end

            -- processing unsigned integer, integer or enum (8 bits)
            if dataTypeIndex == 17 or dataTypeIndex == 15  or dataTypeIndex == 22 then
                -- BYTES[14,end] : int type
                t_data:add(IntegerValue, buffer(offset+1,dataLen-1))
                value = buffer(offset+1,dataLen-1):uint()
            end

            -- processing octet string or visible string
            if dataTypeIndex == 9 or dataTypeIndex == 10 then
                -- TODO: there may be some offsets / length errors in here!
                -- BYTE[14] : data length
                t_data:add(DataStringLen,buffer(offset+1,1))
                -- get dataLen from the OCTET STRING format
                -- BYTE[15] : data length
                dataLen = buffer(offset+2,1):uint()
                -- BYTES[16,end] : string value.
                t_data:add(StringValue,buffer(offset+3,dataLen))
                value = buffer(offset+3,dataLen)
            end
            pinfo.cols['info'] = SetRequestVALS[setRequestType]..", OBIS="..obis..", attr="..attribute..", value="..value
        end 
    end
    
    if dlms_type == 0xc4 then
        -- processing DLMS.GetResponse
        -- offset = 0
        
        t_dlms:add(GetResponse,buffer(offset+1,1))

        -- BYTE[1] = response type
        local responseType = buffer(offset+1,1):uint()

        -- from BYTE[5,end] is where many of the data types below exist; fixed length based on data size.
        local dataLen = frame_len-5
        local dataTypeIndex = 0

        -- BYTE[2] = response invoke id
        t_dlms:add(Response_invoke_id,buffer(offset+2,1))

        if responseType == 1 then 
            -- GetNormalResponse
            -- BYTES[3,end] : data
            local t_data = t_dlms:add(buffer(offset+3,frame_len-3),"Data")

            -- hard offset advance.
            offset = offset+3
            -- BYTE[3] = type of response data
            t_data:add(Response_getData,buffer(offset,1))

            if buffer(offset,1):uint() == 0 then 
                -- CHOICE Data
                -- BYTE[4] : datatype index
                t_data:add(DataType,buffer(offset+1,1))
                dataTypeIndex = buffer(offset+1,1):uint()

                if dataTypeIndex == 9  then
                    -- processing octet string
                    t_data:add(DataStringLen,buffer(offset+2,1))
                    -- get dataLen from the OCTET STRING format
                    -- BYTE[5] : data string len (specified size GREAT FOR FUZZING)
                    dataLen = buffer(offset+2,1):uint()
                    -- BYTES[6,6+dataLen] : string data.
                    t_data:add(StringValue,buffer(offset+3,dataLen))
                end

                if dataTypeIndex == 10 then
                    -- processing visible string
                    t_data:add(DataStringLen,buffer(offset+2,1))
                    -- get dataLen from the OCTET STRING format
                    -- BYTE[5] : data string len (specified size GREAT FOR FUZZING)
                    dataLen = buffer(offset+2,1):uint()
                    -- BYTES[6,6+dataLen] : string data.
                    t_data:add(buffer(offset+3,dataLen),"Value:",PrintString(dataLen,buffer(offset+3)))
                end

                -- processing long integer or long unsigned (16 bits)
                if dataTypeIndex == 16 or dataTypeIndex == 18 then 
                    -- BYTES[5,end]: long value
                    t_data:add(LongValue,buffer(offset+2,dataLen))
                end

                -- processing Boolean (8 bits)
                if dataTypeIndex == 3 then
                    -- BYTES[5,end]: bool value
                    t_data:add(BooleanValue, buffer(offset+2,dataLen))
                end

                -- processing unsigned integer, integer or enum (8 bits)
                if dataTypeIndex == 17 or dataTypeIndex == 15  or dataTypeIndex == 22 then
                    -- BYTES[5,end]: int value
                    t_data:add(IntegerValue, buffer(offset+2,dataLen))
                end

                -- processing double long and double long unsigned (32 bits)
                if dataTypeIndex == 5 or dataTypeIndex == 6 then
                    -- BYTES[5,end]: double value
                    t_data:add(DoubleLongValue, buffer(offset+2,dataLen))
                end

                -- processing long64 and long64 unsigned (64 bits)
                if dataTypeIndex == 20 or dataTypeIndex == 21 then
                    -- BYTES[5,end]: long64 value
                    t_data:add(Long64Value, buffer(offset+2,dataLen))
                end

                -- processing structure and array (sequence of data)
                if dataTypeIndex == 1 or dataTypeIndex == 2 then
                    -- BYTES[5,end]: string value
                    t_data:add(StringValue,buffer(offset+2,dataLen))
                end
                pinfo.cols['info'] = GetResponseVALS[responseType]..", "..GetDataTypeVALS[dataTypeIndex].." ("..dataLen.." bytes)"

            else                                  
                -- CHOICE data-access-result
                -- BYTE[5]: result
                local result = buffer(offset+2,1):uint()
                t_data:add(buffer(offset+2,1),"DataAccessResult:",DataAccessResultVALS[result].." ("..result..")")
                pinfo.cols['info'] = GetResponseVALS[responseType]..", "..DataAccessResultVALS[result].." ("..dataLen.." bytes)"
            end
        end

        if responseType == 2 then 
            -- GetResponseWithDatablock
            -- offset = 0

            -- BYTES[3,end] = data block
            local t_dataBlock = t_dlms:add(buffer(offset+3, frame_len-3),"DataBlock-G")

            -- hard offset advance. offset = [3]
            offset = offset+3

            -- BYTE[3] = last block flag?
            t_dataBlock:add(LastBlock, buffer(offset,1))
            -- BYTES[4,8) : block number
            local blockNumber = buffer(offset+1,4):uint()
            t_dataBlock:add(BlockNumber, buffer(offset+1,4))
            -- BYTE[8] : block result
            t_dataBlock:add(DataBlockResult, buffer(offset+5,1))
            local result = buffer(offset+5,1):uint()

            if result == 0 then 
                -- raw data, i.e., OCTET STRING
                -- length of raw data in this frame
                -- TODO: we already removed 5 bytes. Is this an error?
                dataLen = dataLen - 5    
                dataTypeIndex = 9
                -- BYTE[9] : block length
                local dataBlockLen = buffer(offset+6,1):uint()

                -- hard offset advance: offset = [9]
                offset = offset + 6

                -- processing ASN.1 variable-length integers
                if dataBlockLen <= 127 then 
                    -- the length is one byte only
                    -- BYTE[9] : data string length
                    t_dataBlock:add(DataStringLen, buffer(offset,1))

                else 
                    -- the length is more than one byte (dataBlockLen > 127)
                    -- get the length of the length field
                    local LenBytes = dataBlockLen - 128  
                    -- BYTE[10] = length value
                    local LenValue = buffer(offset+1,LenBytes):uint()

                    -- BYTES[9,len] = data string / byte string.
                    t_dataBlock:add(DataStringLen, buffer(offset,LenBytes+1), LenValue)

                    -- hard advance offset by value in packet
                    -- NOTE: Great FUZZ field.
                    offset = offset + LenBytes
                end

                -- BYTES[9+lenBytes,end] = string value.
                t_dataBlock:add(StringValue,buffer(offset,dataLen-1)) 
            end
            pinfo.cols['info'] = GetResponseVALS[responseType].." no. "..blockNumber..", "..GetDataTypeVALS[dataTypeIndex].." ("..dataLen.." bytes)"
        else
            pinfo.cols['info'] = GetResponseVALS[responseType]..", "..GetDataTypeVALS[dataTypeIndex].." ("..dataLen.." bytes)"
        end
    end

    if dlms_type == 0xc5 then
        -- processing DLMS.SetResponse
        -- offset = 0
        t_dlms:add(SetResponse,buffer(offset+1,1))

        -- BYTE[1] : response type
        local responseType = buffer(offset+1,1):uint()
        -- BYTE[2] : response invoke id
        t_dlms:add(Response_invoke_id,buffer(offset+2,1))

        if responseType == 1 then 
            -- SetNormalResponse
            t_dlms:add(DataAccessResult, buffer(offset+3,1))
            -- BYTE[3] : data access response
            local response = buffer(offset+3,1):uint()
            pinfo.cols['info'] = SetResponseVALS[responseType]..", result="..response.." ("..DataAccessResultVALS[response]..")"
        end
    end
    
    if dlms_type == 0x60 then                       
        -- processing DLMS.AARQ (encoded by BER using TLV structures)
        -- type (application tag AARQ)
        -- offset = 0
        -- the length of the TLV value
        -- BYTE[1] : buffer length
        local bufferLen = buffer(offset+1,1):uint()  

        t_dlms:add(buffer(offset+1,1),"Length:",bufferLen)

        -- BYTE[2] -- actually BITS[4:0]: tag type
        local type = GetTagNumber(buffer:range(2,1)) -- type (AARQ field)
        -- BYTE[3] : length
        local len = buffer(offset+3,1):uint()        -- the length of the embedded TLV
        bufferLen = bufferLen - len -2

        -- hard offset change: offset = [4]
        offset = offset + 4
        if type == 1 then 
            -- type Application Context
            if buffer(offset,1):uint() == 0x06 then   
                -- type OID
                -- the length of the embedded TLV
                -- BYTE[5] : length
                len = buffer(offset+1,1):uint()        
                -- BYTES[6,13) : OID identifier
                local oid = PrintOID(buffer(offset+2,7))
                -- BYTES[6,6+len]
                -- BYTES[11,13) : context vals
                t_dlms:add(buffer(offset+2,len),"ApplicationContextName:", oid.." ("..ContextVALS[buffer(offset+7,2):uint()]..")")

                -- hard offset change: offset = [13]
                offset = offset + 9
            end
        end

        if bufferLen > 0 then
            -- more data available
            -- BYTE[4] : tag type
            type = GetTagNumber(buffer:range(offset,1))
            if type == 10 then                      -- sender ACSE requirements
                -- BYTE[5] : length
                len = buffer(offset+1,1):uint()
                local acse = GetBitStringValue(buffer(offset+2,len))
                t_dlms:add(buffer(offset+2,len),"SenderACSErequirements:",ACSErequirementsVALS[acse].." ("..acse..")")
                offset = offset + 2 + len

                -- indicates when we are done.
                bufferLen = bufferLen - 2 - len
            end
        end

        if bufferLen > 0 then
            -- more data available
            -- BYTE[4] : tag type
            type = GetTagNumber(buffer:range(offset,1))
            if type == 11 then                      -- mechanism name
                -- BYTE[5] : length
                len = buffer(offset+1,1):uint()
                local oid = PrintOID(buffer(offset+2,len))
                t_dlms:add(buffer(offset+2,len),"MechanismName:",oid.." ("..ContextVALS[buffer(offset+7,2):uint()]..")")
                offset = offset + 2 + len

                -- indicates when we are done.
                bufferLen = bufferLen - 2 - len
            end
        end

        if bufferLen > 0 then
            -- more data available
            -- BYTE[4] : tag type
            type = GetTagNumber(buffer:range(offset,1))
            if type == 12 then                      -- calling authentication value
                -- BYTE[5] : length
                len = buffer(offset+1,1):uint()
                -- BYTE[6]
                type = GetTagNumber(buffer:range(offset+2,1)) -- get CHOICE tag
                if type == 0 then -- charstring
                    -- hard offset change = [6]
                    offset = offset + 2               -- move to the charstring
                    -- BYTE[7]
                    len = buffer(offset+1,1):uint()   -- the length of the string
                end
                -- offset 4 or 6
                -- BYTES[4|6,end]
                t_dlms:add(buffer(offset+2,len),"CallingAuthenticationValue:",PrintString(len,buffer(offset+2,len)))

                -- hard offset change = [6|8 + len]
                offset = offset + 2 + len

                -- indicates when we are done.
                bufferLen = bufferLen - 2 - len
            end
        end

        if bufferLen > 0 then
            -- more data available
            -- BYTE[4] : tag type
            type = GetTagNumber(buffer:range(offset,1))
            if type == 30 then                       -- type user information 
                -- BYTE[5] : length
                len = buffer(offset+1,1):uint()       -- the length of the embedded TLV
                -- BYTE[6]
                if buffer(offset+2,1):uint() == 0x04 then -- type OCTET STRING
                    -- BYTE[7]
                    len = buffer(offset+3,1):uint()        -- the length of the string
                    -- BYTE[8]
                    if buffer(offset+4,1):uint() == 0x01 then -- initiateRequest tag
                        -- hard offset change offset = [8]
                        offset = offset+4
                        -- BYTES[8,end]: 
                        local t_request = t_dlms:add(buffer(offset,len),"UserInformation:","xDLMS-Initiate.request")
                        
                        -- BYTE[8]: 
                        local t_request = t_dlms:add(buffer(offset,len),"UserInformation:","xDLMS-Initiate.request")
                        -- BYTE[9]: 
                        local item = buffer(offset+1,1):uint() -- OPTIONAL dedicated-key
                        if item == 0 then -- key not present: boolean value
                            -- BYTE[9]: 
                            t_request:add(buffer(offset+1,1),"DedicatedKey:",BooleanVALS[item].."("..item..")")
                            -- hard offset change offset = [10]
                            offset=offset+2
                        else              -- key present: OCTET STRING
                            -- hard offset change offset = [9]
                            offset = offset + 1
                            -- BYTE[9] : length
                            len = buffer(offset,1)
                            -- BYTES[10,end] : string
                            local str = tostring(buffer(offset+1,len))
                            t_request:add(buffer(offset+1,len),"DedicatedKey:",str)
                            -- hard offset change base on len field NOTE: Good FUZZ Target
                            offset = offset+1+len
                        end
                        -- offset has been updated in various ways!
                        
                        -- BYTE[10+]
                        item = buffer(offset,1):uint()
                        t_request:add(buffer(offset,1),"ResponseAllowed:",BooleanVALS[item].."("..item..")")
                        -- hard offset change +1
                        offset = offset+1

                        -- BYTE[11+]
                        item = buffer(offset,1):uint()
                        t_request:add(buffer(offset,1),"ProposedQualityOfService:",BooleanVALS[item].."("..item..")")
                        offset = offset+1
                        -- BYTE[12+]
                        item = buffer(offset,1):uint()
                        t_request:add(buffer(offset,1),"ProposedDLMSversionNumber:",item)
                        offset = offset+1
                        -- BYTE[13+]
                        t_request:add(buffer(offset,7),"ProposedConformance:",tostring(buffer(offset,7)))

                        -- hard offset change +7
                        offset = offset+7

                        -- BYTE[20+]
                        t_request:add(buffer(offset,2),"ClientMaxReceivedPDUsize:", buffer(offset,2):uint())
                    end
                end
            end
        end
    end

    if dlms_type == 0x61 then                       
        -- processing DLMS.AARE (encoded by BER using TLV structures)
        -- type (application tag AARE)
        -- offset = 0
        -- frame_len = size of frame.
        -- BYTE[1] : buffer length
        local bufferLen = buffer(offset+1,1):uint()  -- the length of the TLV value
        t_dlms:add(buffer(offset+1,1),"Length:",bufferLen)

        -- BYTE[2] : tag type
        local type = GetTagNumber(buffer:range(2,1)) -- type (AARQ field)
        -- BYTE[3] : length
        local len = buffer(offset+3,1):uint()        -- the length of the embedded TLV

        -- bufferLen : packet data dependent.
        bufferLen = bufferLen - len -2
        -- hard change offset = [4]
        offset = offset + 4

        if type == 1 then 
            -- type Application Context
            -- BYTE[4]
            if buffer(offset,1):uint() == 0x06 then   
                -- type OID
                -- the length of the embedded TLV
                -- BYTE[5]
                len = buffer(offset+1,1):uint()        
                -- BYTES[6,13)] : OID
                local oid = PrintOID(buffer(offset+2,7))
                -- BYTES[6,end)] : OID
                -- BYTES[11,13) : context vals
                t_dlms:add(buffer(offset+2,len),"ApplicationContextName:", oid.." ("..ContextVALS[buffer(offset+7,2):uint()]..")")
                -- hard offset change = [13]
                offset = offset + 9

                -- doesn't change bufferLen
                -- changes offset
            end
        end

        if bufferLen > 0 then
            -- more data available
            -- BYTE[4+?]
            type = GetTagNumber(buffer:range(offset,1))
            if type == 2 then                      
                -- association result
                -- BYTE[5+?] : length
                len = buffer(offset+1,1):uint()
                -- BYTE[8+?] : result
                local result = buffer(offset+4,1):uint() -- INTEGER type
                t_dlms:add(buffer(offset+4,1),"AssociationResult:",AssociationResultVALS[result].." ("..result..")")
                -- hard offset change = [6+?+len]
                offset = offset + 2 + len
                bufferLen = bufferLen - 2 - len
                pinfo.cols['info'] = "DLMS "..COSEMpdu[dlms_type]..": "..AssociationResultVALS[result]

                -- changes bufferLen and offset
            end
        end
        
        if bufferLen > 0 then
            -- more data available
            -- BYTE[4+?]
            type = GetTagNumber(buffer:range(offset,1))
            if type == 3 then                      
                -- result source diagnostic
                -- BYTE[5+?]
                len = buffer(offset+1,1):uint()
                -- BYTE[6+?]
                type = GetTagNumber(buffer:range(offset+2,1)) 
                if type == 1 then                   
                    -- acse-service user
                    -- BYTE[10+?]
                    local result = buffer(offset+6,1):uint()
                    t_dlms:add(buffer(offset+6,1),"ResultSourceDiagnostic:",ASCEserviceUserVALS[result].." ("..result..")")
                else
                    t_dlms:add(buffer(offset+6,1),"ResultSourceDiagnostic:",ASCEserviceProvideVALS[result].." ("..result..")")
                end

                -- hard offset change = [6+?+len]
                offset = offset + 2 + len
                bufferLen = bufferLen - 2 - len

                -- changes bufferLen and offset
            end
        end

        if bufferLen > 0 then
            -- more data available
            type = GetTagNumber(buffer:range(offset,1))
            if type == 8 then                      -- responder ACSE requirements
                len = buffer(offset+1,1):uint()
                local acse = GetBitStringValue(buffer(offset+2,len))
                t_dlms:add(buffer(offset+2,len),"SenderACSErequirements:",ACSErequirementsVALS[acse].." ("..acse..")")
                offset = offset + 2 + len
                bufferLen = bufferLen - 2 - len
            end
        end
        
        if bufferLen > 0 then
            -- more data available
            type = GetTagNumber(buffer:range(offset,1))
            if type == 9 then                      -- mechanism name
                len = buffer(offset+1,1):uint()
                local oid = PrintOID(buffer(offset+2,len))
                t_dlms:add(buffer(offset+2,len),"MechanismName:",oid.." ("..ContextVALS[buffer(offset+7,2):uint()]..")")
                offset = offset + 2 + len
                bufferLen = bufferLen - 2 - len
            end
        end

        if bufferLen > 0 then
            -- more data available
            type = GetTagNumber(buffer:range(offset,1))
            if type == 10 then                      -- responding authentication value
                len = buffer(offset+1,1):uint()
                type = GetTagNumber(buffer:range(offset+2,1)) -- get CHOICE tag
                if type == 0 then -- charstring
                    offset = offset + 2               -- move to the charstring
                    len = buffer(offset+1,1):uint()   -- the length of the string
                end
                t_dlms:add(buffer(offset+2,len),"CallingAuthenticationValue:",PrintString(len,buffer(offset+2,len)))
                offset = offset + 2 + len
                bufferLen = bufferLen - 2 - len
            end
        end

        if bufferLen > 0 then
            -- more data available
            type = GetTagNumber(buffer:range(offset,1))
            if type == 30 then                       -- type user information 
                len = buffer(offset+1,1):uint()       -- the length of the embedded TLV
                if buffer(offset+2,1):uint() == 0x04 then -- type OCTET STRING
                    len = buffer(offset+3,1):uint()        -- the length of the string
                    if buffer(offset+4,1):uint() == 0x08 then -- initiateResponse tag
                        offset = offset+4
                        local t_request = t_dlms:add(buffer(offset,len),"UserInformation:","xDLMS-Initiate.response")
                        local item = buffer(offset+1,1):uint() -- OPTIONAL negotiated-quality-of-service
                        t_request:add(buffer(offset+1,1),"NegotiatedQualityOfService:",item)
                        offset=offset+2

                        item = buffer(offset,1):uint()
                        t_request:add(buffer(offset,1),"NegotiatedDLMSversion:",item)
                        offset = offset+1
                        t_request:add(buffer(offset,7),"ProposedConformance:",tostring(buffer(offset,7)))
                        offset = offset+7
                        t_request:add(buffer(offset,2),"ClientMaxReceivedPDUsize:", buffer(offset,2):uint())
                        offset = offset+2
                        t_request:add(buffer(offset,2),"VAAname:", buffer(offset,2):uint())
                    end
                end
            end
        end
    end
end

-- returns tag number (last 5 bits of the identifier byte) of the TLV
function GetTagNumber (tag)
   return tag:bitfield(3,5)
end

-- returns OID value as a formatted string of 7 bytes
-- expects DLMS prefix 2.16.756.5.8.x.x which has a compact BER encoding
function PrintOID (oid)
   if oid(0,3):uint() == 0x608574 then -- BER encoded OID value 2+16 and 756
      return string.format("2.16.756.%d.%d.%d.%d",oid(3,1):uint(),oid(4,1):uint(),oid(5,1):uint(),oid(6,1):uint())
   else
      return string.format("%d.%d.%d.%d.%d.%d.%d",oid(0,1):uint(),oid(1,1):uint(),oid(2,1):uint(),oid(3,1):uint(),oid(4,1):uint(),oid(5,1):uint(),oid(6,1):uint())
   end
end

-- returns a bit string value from BER encoded BITSTRING
function GetBitStringValue (str)
   local len = str:len()-1            -- no. of bytes with BITSTRING without the unused bits number
   local unused = str(0,1):uint()     -- no. of unused bits (the first byte of the BITSTRING)
   local bitstring = str:range(1,len) -- the value of the BITSTRING
   return bitstring:bitfield(0,len*8-unused)
end

-- returns an ASCII string from a HEX bytes, e
function PrintString (len, str)
   local printable = ""
   for i = 0,len-1,1 do
      printable = printable..string.char(str(i,1):uint())
   end
   return printable
end


-- load the tcp port table
-- tcp_table = DissectorTable.get("tcp.port")
-- register the protocol to port 4061
-- tcp_table:add(4061, dlms_proto)
