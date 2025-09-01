-- Get distro (once, cached)
local distro_cache = nil
local function get_distro()
  if distro_cache then return distro_cache end
  local f = io.open("/etc/os-release", "r")
  if not f then return "Unknown" end
  for line in f:lines() do
    local name = line:match('PRETTY_NAME="?(.-)"?$')
    if name then
      distro_cache = name
      break
    end
  end
  f:close()
  return distro_cache or "Unknown"
end

-- Get uptime (parse /proc/uptime)
local function get_uptime()
  local f = io.open("/proc/uptime", "r")
  if not f then return "0:00" end
  local up = f:read("*n")
  f:close()
  local days = math.floor(up / 86400)
  local hours = math.floor((up % 86400) / 3600)
  local mins  = math.floor((up % 3600) / 60)
  if days > 0 then
    return string.format("%dd %02dh %02dm", days, hours, mins)
  else
    return string.format("%02dh %02dm", hours, mins)
  end
end

-- System info print
function conky_sysinfo_box()
  local user  = conky_parse("${uid_name 1000}")
  local host  = conky_parse("${nodename}")
  local kern  = conky_parse("${kernel}")
  local distro = get_distro()
  local uptime = get_uptime()

  local r3 = "${alignr 3}"

  local box  = r3 .. string.format("%s@%s :   host ─┐\n", user, host)
  box = box .. r3 .. "│\n"
  box = box .. r3 .. string.format("%s : kernel ─┤\n", kern)
  box = box .. r3 .. string.format("%s : distro ─┤\n", distro)
  box = box .. r3 .. string.format("%s : uptime ─┘", uptime)

  return box
end

function conky_cpu_box()
	-- Read CPU model
	local f = io.open("/proc/cpuinfo", "r")
	local cpuinfo = f:read("*all")
	f:close()

	local cpu_model = cpuinfo:match("model name%s*:%s*(.-)\n") or "Unknown CPU"
	cpu_model = cpu_model:gsub("%(R%)", ""):gsub("%(TM%)", ""):gsub("CPU", "")
	cpu_model = cpu_model:sub(1, 42)

	-- Calculate average frequency
	local freq_sum, count = 0, 0
	for mhz in cpuinfo:gmatch("cpu MHz%s*:%s*([%d%.]+)") do
		freq_sum = freq_sum + tonumber(mhz)
		count = count + 1
	end
	local avg_ghz = string.format("%.2f GHz", freq_sum / count / 1000)

	-- Build the box
	local alr = "${alignr 10}"

	local box = alr
		.. "┌──────────────────────────────────────────┐\n"
	box = box .. alr .. "│  " .. cpu_model .. "  │\n"
	box = box
		.. alr
		.. "├──────────────────────────────────────────┤\n"
	box = box .. alr .. "│ processes - " .. conky_parse("${processes}") .. "               <" .. avg_ghz .. "> │\n"
	box = box
		.. alr
		.. "├──────────────────────────────────────────┤\n"

	for i = 1, 5 do
		local pname = conky_parse("${top name " .. i .. "}")
		local pcpu = conky_parse("${top cpu " .. i .. "}")
		box = box .. string.format(alr .. "├─ p%d <%s            %s> │\n", i, pname, pcpu)
	end

	box = box
		.. alr
		.. "└──────────────────────────────────────────┘\n"
	box = box .. "${alignr 20}└─────── cpu ${offset 3}"
	return box
end
