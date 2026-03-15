-- cascade_revoke.lua
-- Atomically revoke a credential and all descendants in the delegation tree.
--
-- ARGV[1]: credential_id (root of the subtree to revoke)
-- ARGV[2]: max_depth (safety cap, typically 10)
--
-- Returns: total count of credentials whose status was set to REVOKED

local function cascade(cred_id, max_depth, depth)
    if depth >= max_depth then
        return 0
    end

    local key = "navil:cred:" .. cred_id
    local status = redis.call("HGET", key, "status")
    if not status then
        return 0
    end

    local count = 0
    if status ~= "REVOKED" then
        redis.call("HSET", key, "status", "REVOKED")
        count = 1
    end

    -- Get children from the parent→children set
    local children_key = key .. ":children"
    local children = redis.call("SMEMBERS", children_key)
    for _, child_id in ipairs(children) do
        count = count + cascade(child_id, max_depth, depth + 1)
    end

    return count
end

return cascade(ARGV[1], tonumber(ARGV[2]), 0)
