--- Lua client for the SMS Gora SMS Gateway API (https://tekservix.com/smsgora/).
--
--   local smsgora = require "smsgora"
--   local sms = smsgora.new{ api_key = os.getenv("SMSGORA_KEY") }
--   local result, err = sms:send_sms{ to = "+15551234567", message = "Your code is 482913" }
--
-- Every method returns `data` on success, or `nil, err` where err is a table with
-- status, message, errors, body and retry_after. Keep the API key on your server.

local hmac = require "smsgora.hmac"

local ok_json, json = pcall(require, "cjson")
if not ok_json then json = require "dkjson" end

local M = { _VERSION = "1.0.0" }
M.DEFAULT_BASE_URL = "https://tekservix.com/smsgora/api/v1"

local Client = {}
Client.__index = Client

-- Default transport: LuaSocket + LuaSec. Returns status, body, headers.
local function default_http(method, url, headers, body)
  local ltn12 = require "ltn12"
  local requester = url:match("^https:") and require("ssl.https") or require("socket.http")
  local chunks = {}
  local _, status, resp_headers = requester.request {
    method = method,
    url = url,
    headers = headers,
    source = body and ltn12.source.string(body) or nil,
    sink = ltn12.sink.table(chunks),
  }
  if type(status) ~= "number" then return nil, tostring(status) end
  return status, table.concat(chunks), resp_headers or {}
end

local function esc(s)
  return (tostring(s):gsub("[^%w%-%._~]", function(c) return string.format("%%%02X", c:byte()) end))
end

local function query(params)
  local keys = {}
  for k, v in pairs(params or {}) do
    if v ~= nil and tostring(v) ~= "" then keys[#keys + 1] = k end
  end
  table.sort(keys)
  if #keys == 0 then return "" end
  local parts = {}
  for i, k in ipairs(keys) do parts[i] = esc(k) .. "=" .. esc(params[k]) end
  return "?" .. table.concat(parts, "&")
end

local function decode(text)
  if text == nil or text == "" then return nil end
  local ok, value = pcall(json.decode, text)
  if ok and value ~= json.null then return value end
  return nil
end

--- Create a client.
-- opts.api_key (required), opts.base_url, opts.http = function(method, url, headers, body) -> status, body, headers
function M.new(opts)
  assert(type(opts) == "table" and type(opts.api_key) == "string" and opts.api_key ~= "",
    "smsgora: api_key is required (create one in SMS Gora -> API keys)")
  return setmetatable({
    api_key = opts.api_key,
    base_url = (opts.base_url or M.DEFAULT_BASE_URL):gsub("/+$", ""),
    http = opts.http or default_http,
  }, Client)
end

--- Call any documented endpoint, e.g. sms:request("GET", "/devices").
function Client:request(method, path, body)
  local headers = {
    ["x-api-key"] = self.api_key,
    ["accept"] = "application/json",
    ["user-agent"] = "smsgora-lua/" .. M._VERSION,
  }
  local payload
  if body ~= nil then
    payload = json.encode(body)
    headers["content-type"] = "application/json"
    headers["content-length"] = tostring(#payload)
  end

  local status, text, resp_headers = self.http(method:upper(), self.base_url .. path, headers, payload)
  if not status then
    return nil, { status = 0, message = "request failed: " .. tostring(text) }
  end
  local data = decode(text)
  local failed = type(data) == "table" and data.success == false
  if status >= 400 or failed then
    local retry = resp_headers and (resp_headers["retry-after"] or resp_headers["Retry-After"])
    return nil, {
      status = status,
      message = type(data) == "table" and type(data.message) == "string" and data.message or ("HTTP " .. status),
      errors = type(data) == "table" and data.errors or nil,
      body = data or text,
      retry_after = tonumber(retry),
    }
  end
  if type(data) == "table" and data.data ~= nil then return data.data end
  return data
end

--- Send an SMS. args.to (string or list, up to 1,000), args.message, args.device_id,
-- args.sim_slot (0 = SIM 1, 1 = SIM 2), args.schedule_at (ISO 8601).
function Client:send_sms(args)
  local to = args.to
  if type(to) == "string" then
    local list = {}
    for n in to:gmatch("[^,%s]+") do list[#list + 1] = n end
    to = list
  end
  if type(to) ~= "table" or #to == 0 then return nil, { status = 0, message = "send_sms: at least one recipient is required" } end
  local body = { recipients = to, message = args.message, sim_slot = args.sim_slot, schedule_at = args.schedule_at }
  local path = args.device_id and ("/devices/" .. esc(args.device_id) .. "/send-sms") or "/send-sms"
  return self:request("POST", path, body)
end

--- Different texts for different people in one call (up to 5,000 recipients).
-- messages = { { recipients = {...}, message = "own text" }, ... }
function Client:send_bulk_sms(device_id, messages, message_template)
  return self:request("POST", "/devices/" .. esc(device_id) .. "/send-bulk-sms",
    { messages = messages, messageTemplate = message_template })
end

function Client:get_message(id) return self:request("GET", "/messages/" .. esc(id)) end
function Client:cancel_message(id) return self:request("POST", "/messages/" .. esc(id) .. "/cancel") end
function Client:list_messages(filters) return self:request("GET", "/messages" .. query(filters)) end

function Client:list_received_sms(filters)
  filters = filters or {}
  local rest = {}
  for k, v in pairs(filters) do if k ~= "device_id" then rest[k] = v end end
  local path = filters.device_id and ("/devices/" .. esc(filters.device_id) .. "/get-received-sms") or "/received-sms"
  return self:request("GET", path .. query(rest))
end

function Client:get_batch(id) return self:request("GET", "/batches/" .. esc(id)) end
function Client:list_devices() return self:request("GET", "/devices") end
function Client:get_device(id) return self:request("GET", "/devices/" .. esc(id)) end
function Client:get_account() return self:request("GET", "/account") end
function Client:list_webhooks() return self:request("GET", "/webhooks") end

function Client:create_webhook(url, events, device_id)
  return self:request("POST", "/webhooks", { url = url, events = events or { "sms.received" }, device_id = device_id })
end

function Client:delete_webhook(id) return self:request("DELETE", "/webhooks/" .. esc(id)) end

--- Check the X-SmsGora-Signature header (sha256=<hex HMAC-SHA256 of the raw body>).
function M.verify_webhook(raw_body, signature, secret)
  if type(raw_body) ~= "string" or raw_body == "" or type(signature) ~= "string" or signature == ""
    or type(secret) ~= "string" or secret == "" then
    return false
  end
  return hmac.equal("sha256=" .. hmac.hmac_sha256_hex(secret, raw_body), signature)
end

return M
