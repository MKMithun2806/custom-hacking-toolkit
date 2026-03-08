local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local math = require "math"
local string = require "string"

local targets = {
  "/",
  "/index.html",
  "/cgi-bin/luci",
  "/admin",
  "/config",
  "/api/v1/info",
  "/etc/config/network"
}

local user_agents = {
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0"
}

local description = [[
  Mitchaster's Red Team Discovery Script (Full Remaster) - Fixed
  Combines path probing, banner grabbing, and data sniffing.
  Specifically tuned to detect OpenWrt/LuCI, reporting detailed HTTP information.
]]

local author = "MitchasterTheMan (Fixed by AI)"
local categories = {"discovery", "vuln", "http"}

-- Targets standard and alternate web ports
portrule = shortport.service({ "http", "https", "http-alt", "https-alt", "radan-http" })

local function getRandomUserAgent()
  local index = math.random(1, #user_agents)
  return user_agents[index]
end

local function extractSnippet(body, limit)
  if not body then return nil end
  local snippet = body:sub(1, limit or 60)
  snippet = snippet:gsub("[

]+", " "):gsub(" +", " ") -- Fixed string issue
  return snippet
end

action = function(host, port)
  local results = {}
  local report_data = {}
  local possible_openwrt = false

  -- Use a random User-Agent for each script run
  local ua = getRandomUserAgent()
  local options = {
    header = {
      ["User-Agent"] = ua,
      ["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
      ["Accept-Language"] = "en-US,en;q=0.5",
      ["Accept-Encoding"] = "gzip, deflate, br",
      ["Connection"] = "keep-alive"
    },
    -- Disable redirection handling to analyze each response manually
    redirect = false
  }

  -- 1. Grab Server Identity and initial response for '/'
  local root_res
  local root_path = "/"
  local status_root = "Timeout"
  local root_err

  -- Try to get initial response, even if it times out, to get some headers
  local success, response = pcall(http.get, host, port, root_path, options)
  if success then
    root_res = response
    status_root = root_res.status or "Unknown Status"
    if root_res.header then
      table.insert(report_data, { name = "Server Banner", value = root_res.header.server or "Hidden/Stealth", header = true })
      if root_res.header["content-type"] then
        table.insert(report_data, { name = "Content-Type", value = root_res.header["content-type"], header = true })
      end
      if root_res.header["x-powered-by"] then
        table.insert(report_data, { name = "X-Powered-By", value = root_res.header["x-powered-by"], header = true })
      end
      if root_res.header["set-cookie"] then
        table.insert(report_data, { name = "Set-Cookie", value = stdnse.to_string(root_res.header["set-cookie"]), header = true })
      end
    end
    if root_res.body then
      local snippet = extractSnippet(root_res.body)
      if snippet then
        table.insert(results, string.format("[-] Root Path (%s) | Snippet: %s...", root_path, snippet))
      end

      -- Basic OpenWrt detection from root if it's HTML
      if (status_root == 200) and root_res.header["content-type"] and string.find(root_res.header["content-type"], "text/html", 1, true) then
        if string.find(root_res.body, "LuCI", 1, true) or string.find(root_res.body, "OpenWrt", 1, true) then
          possible_openwrt = true
          table.insert(report_data, { name = "Potential OpenWrt/LuCI", value = "Detected from root path.", state = "open" })
        end
      end
    end
  else
    root_err = response -- capture error message if pcall fails
    table.insert(results, string.format("[-] Error fetching %s: %s", root_path, root_err))
  end

  -- Add a small random delay before probing other paths for stealth
  stdnse.sleep(math.random(1, 3))

  -- 2. Probe other paths with Data Sniffing and detailed header inspection
  for _, path in ipairs(targets) do
    if path == "/" then goto continue end -- Already processed root

    local response
    local status = "Timeout"
    local err
    local header_info = {}

    local success, resp = pcall(http.get, host, port, path, options)
    if success then
      response = resp
      status = response.status or "Unknown Status"

      if response.header then
        -- Collect common headers
        if response.header["content-type"] then table.insert(header_info, {name="Content-Type", value=response.header["content-type"]}) end
        if response.header.server then table.insert(header_info, {name="Server", value=response.header.server}) end
        if response.header["x-powered-by"] then table.insert(header_info, {name="X-Powered-By", value=response.header["x-powered-by"]}) end
        if response.header["set-cookie"] then table.insert(header_info, {name="Set-Cookie", value=stdnse.to_string(response.header["set-cookie"])}) end
        if response.header["location"] then table.insert(header_info, {name="Location", value=response.header.location}) end
      end

      local line_parts = { string.format("Path: %s", path), string.format("Status: %s", status) }

      if status and (status >= 200 and status < 300) then
        if response.body then
          local snippet = extractSnippet(response.body)
          if snippet then
            table.insert(line_parts, string.format("Data Snippet: %s...", snippet))
          end

          -- Enhanced OpenWrt/LuCI detection
          if (path == "/cgi-bin/luci" or path == "/index.html" or path == "/") and
             response.header["content-type"] and string.find(response.header["content-type"], "text/html", 1, true) then
            if string.find(response.body, "LuCI", 1, true) or string.find(response.body, "OpenWrt", 1, true) then
              possible_openwrt = true
              table.insert(report_data, { name = "Potential OpenWrt/LuCI", value = string.format("Detected via '%s' path.", path), state = "open" })
            end
          end
        end
      elseif status and (status >= 300 and status < 400) then
        local loc = response.header.location or "Unknown"
        table.insert(line_parts, string.format("Redirects to: %s", loc))
      elseif status and status == 403 then
        table.insert(line_parts, "Access Denied.")
        -- Specific check for luci 403 as strong indicator
        if path:find("luci") then
          possible_openwrt = true
          table.insert(report_data, { name = "Potential OpenWrt/LuCI", value = string.format("Detected via 403 Forbidden on path '%s'.", path), state = "open" })
        end
      end

      table.insert(results, table.concat(line_parts, " | "))

      -- Add collected headers to report_data
      for _, h in ipairs(header_info) do
        table.insert(report_data, { name = h.name, value = h.value, header = true })
      end

    else
      err = resp -- capture error message
      table.insert(results, string.format("[-] Error fetching %s: %s", path, err))
    end

    -- Add a small random delay before the next probe
    stdnse.sleep(math.random(1, 3))
    ::continue::
  end

  -- Prepare the report data for nmap.report()
  local final_report = {}
  final_report.name = "OpenWrt/LuCI Discovery"
  final_report.host = host.ip
  final_report.port = port.number
  final_report.protocol = port.protocol
  final_report.state = "open" -- Assuming the service is open if we reached here

  if possible_openwrt then
    final_report.service = "OpenWrt/LuCI"
    final_report.state = "open"
    final_report.detection = "strong" -- Indicates a high confidence detection
    final_report.extra_data = report_data
  else
    final_report.service = "Web Server" -- Generic if not specifically detected
    final_report.state = "open"
    final_report.extra_data = report_data
  end

  -- Use nmap.report for structured output
  return nmap.report(final_report)

end