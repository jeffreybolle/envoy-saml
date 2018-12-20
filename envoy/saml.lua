
local sha256 = require("sha256")

local function encode_url(str)
    return (string.gsub(str, "([^A-Za-z0-9%_%.%-%~])", function(v)
            return string.upper(string.format("%%%02x", string.byte(v)))
    end))
end

local function decode_url(str)
    local str = string.gsub(str, "+", " ")

    return (string.gsub(str, "%%(%x%x)", function(c)
            return string.char(tonumber(c, 16))
    end))
end

local function strip_quotes(str)
    local s = string.gsub(str, "^%s*(.-)%s*$", "%1")

    if string.sub(s, 1, 1) == '"' then
        s = string.sub(s, 2, -2)
    end

    return s
end

local function parse_cookies(header_value)
    local res = {}
    
    if header_value == nil then
        return res
    end

    for pair in string.gmatch(header_value, "[^;]+") do
        local eq = string.find(pair, "=")

        if eq then
            local key = strip_quotes(string.sub(pair, 1, eq - 1))
            local val = strip_quotes(string.sub(pair, eq + 1))

            if not res[key] then
                res[key] = decode_url(val)
            end
        end
    end

    return res
end

local function starts_with(str1, str2)
   return string.sub(str1, 1, string.len(str2)) == str2
end

local SamlHandler = {}
SamlHandler.__index = SamlHandler

function SamlHandler.new(config)
        local self = setmetatable({}, SamlHandler)
        self.config = config
        return self
end

function SamlHandler.on_request(self, request_handle)
    if starts_with(request_handle:headers():get(":path"), '/SAML2/') then
        return
    end
    local cookies = parse_cookies(request_handle:headers():get("cookie"))
    auth_session = cookies["auth_session"]
    if auth_session == nil or auth_session == '' then
        self:do_login(request_handle)
    else
        user = self:validate_auth_session(auth_session)
        if user ~= nil then
            request_handle:headers():add(self.config.user_header, user)
            request_handle:headers():add(self.config.token_header, self.config.token)
        else
            self:do_login(request_handle)
        end
    end
end

function SamlHandler.do_login(self, request_handle)
        local headers, body = request_handle:httpCall(
        self.config.saml_cluster,
        {
            [":method"] = "GET",
            [":path"] = "/SAML2/SSO/LOGIN?RelayState=" .. encode_url(request_handle:headers():get(":path")),
            [":authority"] = self.config.saml_cluster
        },
        nil,
        1000)
        request_handle:respond({
            [":status"] = headers[":status"],
            ["location"] = headers["location"]},
            body)
end

function SamlHandler.validate_auth_session(self, session)
    local first_pipe = string.find(session, "|")
    
    if first_pipe then
        local second_pipe = string.find(session, "|", first_pipe + 1)
        if second_pipe then
            local user = string.sub(session, 1, first_pipe - 1)
            local expiry = string.sub(session, first_pipe + 1, second_pipe - 1)
            local sig = string.sub(session, second_pipe + 1)
            
            local now = os.time()
            
            if now > tonumber(expiry) then
                return nil
            end
            
            local newsig = sha256(user .. "|" .. expiry .. "|" .. self.config.secret_key)
            
            if newsig == sig then
                return user
            else
                return nil
            end
        else
            return nil
        end
    else
        return nil
    end
end

local saml = {
    SamlHandler = SamlHandler
}

return saml