-- normalize.lua
-- Called by Fluent Bit lua filter after the multi-parser filter.
-- Fixes:
--   1. Keeps original syslog line in `message`
--   2. Casts port to integer
--   3. Sets event_action from raw_event
--   4. Marks lines that did not match any parser as parse_failed=true

function process_auth(tag, timestamp, record)
    -- The input `message` field contains the raw syslog line (set via Key in [INPUT])
    -- Preserve it as-is so every event has the original log line.

    if record["src_ip"] == nil or record["src_ip"] == "" then
        -- Unparsed line: mark it but forward untouched
        record["parse_failed"] = true
        record["event_action"]  = "unknown"
        return 1, timestamp, record
    end

    record["parse_failed"] = false

    -- Cast port from string to integer
    if record["port"] ~= nil then
        record["port"] = tonumber(record["port"])
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

    -- Reconstruct `message` from structured fields if it was overwritten
    -- (Fluent Bit parser with Reserve_Data keeps original, but make it explicit)
    if record["message"] == nil or record["message"] == "" then
        local ts    = record["timestamp"] or ""
        local host  = record["host"]    or ""
        local proc  = record["process"] or "sshd"
        local pid   = record["pid"]     or ""
        local user  = record["user"]    or ""
        local ip    = record["src_ip"]  or ""
        local port  = record["port"]    or ""
        record["message"] = string.format(
            "%s %s %s[%s]: %s from %s port %s",
            ts, host, proc, pid, record["event_action"], ip, tostring(port)
        )
    end

    return 1, timestamp, record
end
