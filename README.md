# smsgora (Lua)

[![tests](https://github.com/TekservixHQ/smsgora-lua/actions/workflows/tests.yml/badge.svg)](https://github.com/TekservixHQ/smsgora-lua/actions/workflows/tests.yml)

**SMS Gora SMS Gateway** - official Lua client: send and receive SMS through your own Android phones. By Tekservix.

Lua client for the [SMS Gora SMS Gateway](https://tekservix.com/smsgora/) API.

SMS Gora turns Android phones with ordinary SIM cards into an SMS gateway. Your server calls the API, a linked phone sends the text, and replies and delivery reports come back to you. There's no sender ID registration and no per-message fee from us: your mobile operator bills the texts like any SMS.

- Lua 5.1 to 5.4 and LuaJIT; uses LuaSocket + LuaSec by default, or your own HTTP function (OpenResty, Defold, Love2D tools...)
- Pure-Lua webhook signature check (no C compiler needed)

## Install

```bash
luarocks install smsgora
```

## Quick start

You need a Tekservix account with SMS Gora and an API key (SMS Gora → API keys). Keep it on your server.

```lua
local smsgora = require "smsgora"

local sms = smsgora.new { api_key = os.getenv("SMSGORA_KEY") }

local result, err = sms:send_sms { to = "+15551234567", message = "Your verification code is 482913" }
if not result then error(err.message) end
print(result.message_ids[1])  -- 1873
```

Every method returns the API's `data` on success, or `nil, err` where `err` has `status`, `message`, `errors`, `body` and `retry_after` (seconds, on 429).

## Sending

```lua
-- Several recipients (up to 1,000 per call)
sms:send_sms { to = { "+15551234567", "+447700900123" }, message = "Your order has shipped" }

-- From a chosen phone and SIM, scheduled for later
sms:send_sms {
  to = "+15551234567",
  message = "Reminder: your appointment is tomorrow at 10:00",
  device_id = 42,
  sim_slot = 1,                         -- 0 = SIM 1, 1 = SIM 2
  schedule_at = "2026-12-01T08:00:00Z",
}

-- Different texts for different people in one call (up to 5,000 recipients)
sms:send_bulk_sms(42, {
  { recipients = { "+15551234567" }, message = "Hi Aline, parcel #1042 is ready." },
  { recipients = { "+15557654321" } },
}, "Hello, your parcel is ready for pickup.")
```

## Status, incoming SMS and more

```lua
local msg = sms:get_message(1873)          -- msg.status: queued, dispatched, sent, delivered, failed
sms:cancel_message(1874)                   -- while queued or scheduled
local inbox = sms:list_received_sms { since = "2026-11-01", limit = 50 }
local phones = sms:list_devices()
local account = sms:get_account()
local batch = sms:request("GET", "/batches/311")   -- any other endpoint
```

## OpenResty

Pass your own transport, for example with lua-resty-http:

```lua
local sms = smsgora.new {
  api_key = os.getenv("SMSGORA_KEY"),
  http = function(method, url, headers, body)
    local res, err = require("resty.http").new():request_uri(url, { method = method, headers = headers, body = body })
    if not res then return nil, err end
    return res.status, res.body, res.headers
  end,
}
```

## Webhooks

Add your HTTPS URL in SMS Gora → Webhooks (or with `create_webhook`) and keep the secret. Each request carries `X-SmsGora-Signature: sha256=...`, an HMAC-SHA256 of the raw body:

```lua
-- OpenResty
ngx.req.read_body()
local raw = ngx.req.get_body_data()
if not smsgora.verify_webhook(raw, ngx.var.http_x_smsgora_signature, os.getenv("SMSGORA_WEBHOOK_SECRET")) then
  return ngx.exit(401)
end
```

## More from Tekservix

- [WAservix WhatsApp API Gateway](https://tekservix.com/waservix/): WhatsApp from your own number (`luarocks install waservix`)
- [AI Sales Agent](https://tekservix.com/ai-sales-agent): answers customers on WhatsApp and SMS using your website's content
- [Website to App](https://tekservix.com/mobile-apps): turn your website into Android and iOS apps
- SMS Gora libraries for many more languages: [github.com/TekservixHQ](https://github.com/TekservixHQ)

## License

MIT
