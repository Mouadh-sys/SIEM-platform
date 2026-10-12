-- normalize.lua
-- Called by Fluent Bit lua filter after the multi-parser filter.
-- Fixes:
--   1. Keeps original raw syslog line in `message` for every event
--   2. Casts port to integer
--   3. Sets event_action from raw_event
--   4. Marks lines that did not match any parser as parse_failed=true
--   5. Generates SHA-256 doc_id from raw message for deduplication

local ffi = require("ffi")
ffi.cdef[[
    unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
]]

local function hash_sha256(str)
    if not str or str == "" then return "" end
    local md = ffi.new("unsigned char[32]")
    ffi.C.SHA256(str, #str, md)
    local hex = {}
    for i = 0, 31 do
        hex[#hex + 1] = string.format("%02x", md[i])
    end
    return table.concat(hex)
end

function process_auth(tag, timestamp, record)
    -- Compute deterministic doc_id from the raw message so replays don't duplicate
    if record["message"] ~= nil and record["message"] ~= "" then
        record["doc_id"] = hash_sha256(record["message"])
    end

    if record["src_ip"] == nil or record["src_ip"] == "" then
        -- Unparsed line: mark it but forward untouched with original message
        record["parse_failed"] = true
        record["event_action"] = "unknown"
        return 1, timestamp, record
    end

    record["parse_failed"] = false

    -- Cast port from string to integer
    if record["port"] ~= nil then
        record["port"] = math.floor(tonumber(record["port"]))
    end

    -- Map raw_event -> event_action
    local raw = record["raw_event"] or ""
    if raw == "Failed password" then
        record["event_action"] = "failed_login"
    elseif string.find(raw, "Accepted") then
        record["event_action"] = "accepted_login"
    elseif raw == "Invalid user" then
        record["event_action"] = "invalid_user"
    else
        record["event_action"] = "failed_login"
    end

    -- Drop the temporary extraction field
    record["raw_event"] = nil

    return 1, timestamp, record
end
