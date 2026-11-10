-- Pure-Lua SHA-256 and HMAC-SHA256 for Lua 5.1, 5.2, 5.3, 5.4 and LuaJIT.
-- Used only to check webhook signatures, so speed is not critical.

local floor = math.floor
local MOD = 4294967296 -- 2^32

local band, bor, bxor, bnot, rshift, lshift

if bit32 then -- Lua 5.2
  band, bor, bxor, bnot, rshift, lshift = bit32.band, bit32.bor, bit32.bxor, bit32.bnot, bit32.rshift, bit32.lshift
else
  local ok, bit = pcall(require, "bit") -- LuaJIT (results are signed, normalised below)
  if ok and bit then
    local function u(x) return x % MOD end
    band = function(a, b) return u(bit.band(a, b)) end
    bor = function(a, b) return u(bit.bor(a, b)) end
    bxor = function(a, b) return u(bit.bxor(a, b)) end
    bnot = function(a) return u(bit.bnot(a)) end
    rshift = function(a, n) return u(bit.rshift(a, n)) end
    lshift = function(a, n) return u(bit.lshift(a, n)) end
  else
    -- Lua 5.3+: native operators, loaded as text so older versions can still parse this file.
    local chunk = [[
      local M = 0xFFFFFFFF
      return function(a, b) return a & b & M end,
             function(a, b) return (a | b) & M end,
             function(a, b) return (a ~ b) & M end,
             function(a) return (~a) & M end,
             function(a, n) return (a & M) >> n end,
             function(a, n) return (a << n) & M end
    ]]
    local loader = loadstring or load
    local fn = loader(chunk)
    if fn then
      band, bor, bxor, bnot, rshift, lshift = fn()
    else
      -- Plain Lua 5.1 without a bit library: arithmetic fallback.
      local function bitop(a, b, want)
        local r, p = 0, 1
        a, b = a % MOD, b % MOD
        for _ = 1, 32 do
          local x, y = a % 2, b % 2
          if want(x, y) then r = r + p end
          a, b, p = (a - x) / 2, (b - y) / 2, p * 2
        end
        return r
      end
      local AND = function(x, y) return x == 1 and y == 1 end
      local OR = function(x, y) return x == 1 or y == 1 end
      local XOR = function(x, y) return x ~= y end
      band = function(a, b) return bitop(a, b, AND) end
      bor = function(a, b) return bitop(a, b, OR) end
      bxor = function(a, b) return bitop(a, b, XOR) end
      bnot = function(a) return MOD - 1 - a % MOD end
      rshift = function(a, n) return floor((a % MOD) / 2 ^ n) end
      lshift = function(a, n) return (a * 2 ^ n) % MOD end
    end
  end
end

local function rrot(x, n)
  return bor(rshift(x, n), lshift(x, 32 - n))
end

local function add(...)
  local s = 0
  for i = 1, select("#", ...) do s = s + select(i, ...) end
  return s % MOD
end

local K = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function u32be(n)
  return string.char(floor(n / 16777216) % 256, floor(n / 65536) % 256, floor(n / 256) % 256, n % 256)
end

local function sha256(msg)
  local h = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
  local len = #msg
  msg = msg .. "\128" .. string.rep("\0", (55 - len) % 64) .. u32be(floor(len * 8 / MOD)) .. u32be((len * 8) % MOD)

  local w = {}
  for chunk = 1, #msg, 64 do
    for i = 0, 15 do
      local b1, b2, b3, b4 = msg:byte(chunk + i * 4, chunk + i * 4 + 3)
      w[i] = ((b1 * 256 + b2) * 256 + b3) * 256 + b4
    end
    for i = 16, 63 do
      local s0 = bxor(bxor(rrot(w[i - 15], 7), rrot(w[i - 15], 18)), rshift(w[i - 15], 3))
      local s1 = bxor(bxor(rrot(w[i - 2], 17), rrot(w[i - 2], 19)), rshift(w[i - 2], 10))
      w[i] = add(w[i - 16], s0, w[i - 7], s1)
    end
    local a, b, c, d, e, f, g, hh = h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]
    for i = 0, 63 do
      local S1 = bxor(bxor(rrot(e, 6), rrot(e, 11)), rrot(e, 25))
      local ch = bxor(band(e, f), band(bnot(e), g))
      local t1 = add(hh, S1, ch, K[i + 1], w[i])
      local S0 = bxor(bxor(rrot(a, 2), rrot(a, 13)), rrot(a, 22))
      local maj = bxor(bxor(band(a, b), band(a, c)), band(b, c))
      local t2 = add(S0, maj)
      hh, g, f, e, d, c, b, a = g, f, e, add(d, t1), c, b, a, add(t1, t2)
    end
    h[1], h[2], h[3], h[4] = add(h[1], a), add(h[2], b), add(h[3], c), add(h[4], d)
    h[5], h[6], h[7], h[8] = add(h[5], e), add(h[6], f), add(h[7], g), add(h[8], hh)
  end
  local out = {}
  for i = 1, 8 do out[i] = u32be(h[i]) end
  return table.concat(out)
end

local function xor_pad(key, byte)
  local out = {}
  for i = 1, 64 do out[i] = string.char(bxor(key:byte(i), byte)) end
  return table.concat(out)
end

local M = {}

function M.sha256_hex(msg)
  return (sha256(msg):gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

function M.hmac_sha256_hex(key, msg)
  if #key > 64 then key = sha256(key) end
  key = key .. string.rep("\0", 64 - #key)
  local digest = sha256(xor_pad(key, 0x5c) .. sha256(xor_pad(key, 0x36) .. msg))
  return (digest:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

-- Constant-time string comparison.
function M.equal(a, b)
  if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then return false end
  local diff = 0
  for i = 1, #a do diff = bor(diff, bxor(a:byte(i), b:byte(i))) end
  return diff == 0
end

return M
