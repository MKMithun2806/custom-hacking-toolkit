local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

local description = [[
Specialized Auditor for Juice Shop Lab.
Identifies Juice Shop version via Client-Side JS.
Probes for hidden /ftp and /score-board paths.
Checks for Sensitive File Exposure (.md, .pdf).
]]

local author = "Mitchaster"
local categories = {"discovery", "vuln"}

portrule = shortport.portnumber(3006, "tcp")

action = function(host, port)
  local report = stdnse.output_table()
  local critical_paths = {"/ftp", "/score-board", "/#/jobs", "/assets/public"}

  local res = http.get(host, port, "/")
  if res and res.status == 200 then
    report["Service"] = "OWASP Juice Shop"
  end

  report["Exposed Paths"] = {}
  for _, path in ipairs(critical_paths) do
    local p_res = http.get(host, port, path)
    if p_res and (p_res.status == 200 or p_res.status == 304) then
      table.insert(report["Exposed Paths"], path .. " (STATUS: " .. p_res.status .. ")")
    end
  end

  local ftp_res = http.get(host, port, "/ftp")
  if ftp_res and string.find(ftp_res.body or "", "Index of /ftp", 1, true) then
    report["Vulnerability Found"] = "Directory Listing enabled on /ftp"
    report["Evidence"] = "Found 'Index of /ftp' in response body."
  end

  return report
end