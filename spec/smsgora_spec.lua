local smsgora = require "smsgora"
local hmac = require "smsgora.hmac"
local ok_json, json = pcall(require, "cjson")
if not ok_json then json = require "dkjson" end

local function fake(status, body, headers)
  local calls = {}
  local http = function(method, url, h, payload)
    calls[#calls + 1] = { method = method, url = url, headers = h, body = payload and json.decode(payload) }
    return status or 200, body or '{"success":true,"data":{"message_ids":[1873]}}', headers or {}
  end
  return calls, http
end

describe("smsgora", function()
  it("sends an SMS", function()
    local calls, http = fake()
    local sms = smsgora.new { api_key = "sgk_test", base_url = "https://example.test/api/", http = http }
    local res = assert(sms:send_sms { to = "+15551234567", message = "Hi" })
    assert.are.equal(1873, res.message_ids[1])
    assert.are.equal("POST", calls[1].method)
    assert.are.equal("https://example.test/api/send-sms", calls[1].url)
    assert.are.equal("sgk_test", calls[1].headers["x-api-key"])
    assert.are.same({ "+15551234567" }, calls[1].body.recipients)
    assert.are.equal("Hi", calls[1].body.message)
  end)

  it("uses phone, SIM and schedule", function()
    local calls, http = fake()
    local sms = smsgora.new { api_key = "k", base_url = "https://example.test/api", http = http }
    sms:send_sms { to = "+1, +2", message = "x", device_id = 42, sim_slot = 1, schedule_at = "2026-12-01T08:00:00Z" }
    assert.are.equal("https://example.test/api/devices/42/send-sms", calls[1].url)
    assert.are.same({ "+1", "+2" }, calls[1].body.recipients)
    assert.are.equal(1, calls[1].body.sim_slot)
    assert.are.equal("2026-12-01T08:00:00Z", calls[1].body.schedule_at)
  end)

  it("builds paths and queries", function()
    local calls, http = fake()
    local sms = smsgora.new { api_key = "k", base_url = "https://example.test/api", http = http }
    sms:send_bulk_sms(42, { { recipients = { "+1" }, message = "a" }, { recipients = { "+2" } } }, "t")
    assert.are.equal("https://example.test/api/devices/42/send-bulk-sms", calls[1].url)
    assert.are.equal("t", calls[1].body.messageTemplate)
    sms:list_received_sms { phone = "+1555", since = "2026-11-01" }
    assert.are.equal("https://example.test/api/received-sms?phone=%2B1555&since=2026-11-01", calls[2].url)
    sms:list_received_sms { device_id = 3 }
    assert.are.equal("https://example.test/api/devices/3/get-received-sms", calls[3].url)
    sms:cancel_message(7)
    assert.are.equal("https://example.test/api/messages/7/cancel", calls[4].url)
    sms:create_webhook("https://my.app/hook")
    assert.are.same({ "sms.received" }, calls[5].body.events)
    sms:delete_webhook(9)
    assert.are.equal("DELETE", calls[6].method)
    local res, err = sms:send_sms { to = {}, message = "x" }
    assert.is_nil(res)
    assert.truthy(err.message:find("recipient"))
  end)

  it("returns API errors", function()
    local _, http = fake(429, '{"success":false,"message":"Too many requests","errors":{"recipients":["bad"]}}',
      { ["retry-after"] = "12" })
    local sms = smsgora.new { api_key = "k", http = http }
    local res, err = sms:get_account()
    assert.is_nil(res)
    assert.are.equal(429, err.status)
    assert.are.equal("Too many requests", err.message)
    assert.are.equal(12, err.retry_after)
    assert.are.equal("bad", err.errors.recipients[1])

    local _, http2 = fake(502, "<html>bad gateway</html>")
    local _, err2 = smsgora.new({ api_key = "k", http = http2 }):list_devices()
    assert.are.equal("HTTP 502", err2.message)
    assert.are.equal("<html>bad gateway</html>", err2.body)

    assert.has_error(function() smsgora.new {} end)
  end)

  it("computes SHA-256 and HMAC-SHA256", function()
    assert.are.equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hmac.sha256_hex(""))
    assert.are.equal("b2f2222673f70e4563af636099533dc20d077b754c16c8c3962f57e789350dd0",
      hmac.hmac_sha256_hex(string.rep("k", 100), string.rep("abc", 50)))
  end)

  it("verifies webhooks", function()
    local raw = '{"event":"sms.received","data":{"from":"+15551234567"}}'
    local sig = "sha256=e125c07dfbecb498e8979383d7b9f0815efb128755409794b486d4bbb7199583"
    assert.is_true(smsgora.verify_webhook(raw, sig, "whsec_test"))
    assert.is_false(smsgora.verify_webhook(raw, sig, "other"))
    assert.is_false(smsgora.verify_webhook("{}", sig, "whsec_test"))
    assert.is_false(smsgora.verify_webhook(raw, nil, "whsec_test"))
  end)
end)
