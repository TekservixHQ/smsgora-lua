-- Plain check for LuaJIT (busted cannot be installed there): runs the bit-library path of the HMAC code.
package.path = "src/?.lua;src/?/init.lua;" .. package.path
local hmac = require "smsgora.hmac"
local function check(got, want, what)
  if got ~= want then error(what .. ": got " .. tostring(got) .. ", want " .. tostring(want)) end
  print("ok - " .. what)
end
check(hmac.sha256_hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256 empty")
check(hmac.hmac_sha256_hex(string.rep("k", 100), string.rep("abc", 50)),
  "b2f2222673f70e4563af636099533dc20d077b754c16c8c3962f57e789350dd0", "hmac long key")
check(hmac.hmac_sha256_hex("whsec_test", '{"event":"sms.received","data":{"from":"+15551234567"}}'),
  "e125c07dfbecb498e8979383d7b9f0815efb128755409794b486d4bbb7199583", "webhook vector")
check(hmac.equal("abc", "abc"), true, "equal")
check(hmac.equal("abc", "abd"), false, "not equal")
