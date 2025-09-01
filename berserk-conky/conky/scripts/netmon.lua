-- Individual accessor functions for backward compatibility
function conky_network_dns()
    return get_dns()
end

function conky_network_gateway()
    return get_gateway()
end

function conky_network_ip()
    local primary = get_primary_interface()
    return primary and get_interface_ip(primary) or "na"
end

function conky_network_proxy()
    return get_proxy()
end

function conky_network_primary()
    local primary = get_primary_interface()
    if not primary then return "na" end
    local if_type = classify_interface(primary)
    return primary .. " --- " .. if_type
end-- Enhanced Network Information Script for Conky
-- Supports physical, virtual, container, and tunnel interfaces
-- Author: Enhanced for red team / security research use

require 'io'
require 'string'

-- Utility function to execute shell commands and return output
function exec_cmd(cmd)
    local handle = io.popen(cmd)
    if not handle then return nil end
    local result = handle:read("*a")
    handle:close()
    return result and result:gsub("%s+$", "") or nil
end

-- Check network connectivity
function check_connectivity()
    local ip_output = exec_cmd("ip route get 1.1.1.1 2>&1")
    return ip_output and not string.match(ip_output, "unreachable")
end

-- Get DNS servers
function get_dns()
    local dns_output = exec_cmd("grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | tr '\\n' ' '")
    return dns_output and dns_output:gsub("%s+$", "") or "na"
end

-- Get default gateway
function get_gateway()
    local gw_output = exec_cmd("ip route | grep '^default' | awk '{print $3}' | tr '\\n' ' '")
    return gw_output and gw_output:gsub("%s+$", "") or "na"
end

-- Get IP address for interface
function get_interface_ip(interface)
    local ip_output = exec_cmd("ip addr show " .. interface .. " | grep 'inet ' | head -1 | awk '{print $2}' | cut -d'/' -f1")
    return ip_output or "na"
end

-- Get proxy information
function get_proxy()
    local proxy_output = exec_cmd("env | grep -i https_proxy | head -1 | cut -d'=' -f2")
    return proxy_output and proxy_output ~= "" and proxy_output or "na"
end

-- Classify interface type based on name patterns
function classify_interface(interface)
    local patterns = {
        ["^eth"] = "ethernet",
        ["^en"] = "ethernet", 
        ["^wl"] = "wireless",
        ["^ww"] = "wwan",
        ["^br"] = "bridge",
        ["^docker"] = "docker",
        ["^veth"] = "docker-veth",
        ["^tun"] = "vpn-tunnel",
        ["^tap"] = "tap-tunnel",
        ["^vir"] = "libvirt",
        ["^vmnet"] = "vmware",
        ["^vbox"] = "virtualbox",
        ["^ppp"] = "ppp",
        ["^sit"] = "ipv6-tunnel",
        ["^gre"] = "gre-tunnel",
        ["^ipip"] = "ipip-tunnel",
        ["^vlan"] = "vlan",
        ["^bond"] = "bonding",
        ["^team"] = "teaming",
        ["^can"] = "can-bus"
    }
    
    for pattern, type_name in pairs(patterns) do
        if string.match(interface, pattern) then
            return type_name
        end
    end
    
    return "unknown"
end

-- Get all active network interfaces (excluding loopback)
function get_all_interfaces()
    local interfaces = {}
    -- Get all interfaces that are UP (including those not RUNNING like docker0)
    local cmd_output = exec_cmd("ip link show | grep -E '^[0-9]+:' | grep -E '(state UP|state UNKNOWN)' | awk -F': ' '{print $2}' | awk '{print $1}'")
    
    if not cmd_output then return interfaces end
    
    for interface in cmd_output:gmatch("[^\r\n]+") do
        if interface ~= "lo" and interface ~= "" then
            local ip_addr = get_interface_ip(interface)
            -- Only include interfaces that have an IP address or are important virtual interfaces
            if ip_addr ~= "na" or string.match(interface, "^docker") or string.match(interface, "^tun") or string.match(interface, "^tap") then
                local if_type = classify_interface(interface)
                table.insert(interfaces, {
                    name = interface,
                    ip = ip_addr,
                    type = if_type
                })
            end
        end
    end
    
    return interfaces
end

-- Get primary interface (used for default route)
function get_primary_interface()
    local ip_output = exec_cmd("ip route get 1.1.1.1 2>&1")
    if not ip_output or string.match(ip_output, "unreachable") then
        return nil
    end
    
    local interface = string.match(ip_output, "dev%s+([%w%-%.]+)")
    return interface
end

-- Format interface display with monochrome styling
function format_interface_line(interface, is_primary)
    local shade_codes = {
        ethernet = "${color #ffffff}",      -- White (brightest for primary physical)
        wireless = "${color #ffffff}",      -- White
        docker = "${color #cccccc}",        -- Light gray (containers)
        ["docker-veth"] = "${color #cccccc}", -- Light gray
        ["vpn-tunnel"] = "${color #dddddd}", -- Very light gray (tunnels)
        ["tap-tunnel"] = "${color #dddddd}", -- Very light gray
        bridge = "${color #bbbbbb}",        -- Medium-light gray (bridges)
        libvirt = "${color #aaaaaa}",       -- Medium gray (virtual)
        vmware = "${color #aaaaaa}",        -- Medium gray
        virtualbox = "${color #aaaaaa}",    -- Medium gray
        unknown = "${color #999999}"        -- Darker gray (unknown)
    }
    
    local shade = shade_codes[interface.type] or "${color #ffffff}"
    local ip_display = interface.ip ~= "na" and interface.ip or "no-ip"
    
    return string.format("├─ %s%s${color #666666} (%s) ${color #ffffff}: %s", 
                        shade, interface.name, interface.type, ip_display)
end

-- Main function to display network information with fixed height
function conky_network_info()
    local max_lines = 25  -- Fixed number of lines for consistent spacing
    local lines = {}
    
    if not check_connectivity() then
        table.insert(lines, "network ───── ${color #666666}OFFLINE${color}")
        -- Pad with empty lines at the end
        while #lines < max_lines do
            table.insert(lines, "")
        end
        return table.concat(lines, "\n")
    end
    
    local interfaces = get_all_interfaces()
    if #interfaces == 0 then
        table.insert(lines, "network ───── ${color #666666}NO INTERFACES${color}")
        -- Pad with empty lines at the end
        while #lines < max_lines do
            table.insert(lines, "")
        end
        return table.concat(lines, "\n")
    end
    
    local primary_interface = get_primary_interface()
    local dns = get_dns()
    local gateway = get_gateway()
    local proxy = get_proxy()
    
    -- Build output lines normally (no artificial padding in middle)
    table.insert(lines, "network ───┬─ interfaces active: " .. #interfaces)
    table.insert(lines, "${goto 81}│")
    
    -- Add ALL interfaces (or limit if you prefer, but no padding between)
    for i, interface in ipairs(interfaces) do
        local is_primary = (interface.name == primary_interface)
        local line = format_interface_line(interface, is_primary)
        
        if is_primary then
            line = line .. " ${color #ffffff}[PRIMARY]${color}"
        end
        
        table.insert(lines, "${goto 81}" .. line)
    end
    
    -- Add DNS, Gateway, and Proxy info immediately after interfaces
    table.insert(lines, "${goto 81}│")
    table.insert(lines, "${goto 81}├─ ${color #cccccc}dns${color}      : " .. dns)
    table.insert(lines, "${goto 81}├─ ${color #cccccc}gateway${color}  : " .. gateway)
    
    if proxy ~= "na" then
        table.insert(lines, "${goto 81}└─ ${color #cccccc}proxy${color}    : " .. proxy)
    else
        table.insert(lines, "${goto 81}└─ ${color #666666}proxy${color}    : none")
    end
    
    -- NOW add empty lines at the end to reach max_lines
    while #lines < max_lines do
        table.insert(lines, "")
    end
    
    return table.concat(lines, "\n")
end

-- Calculate dynamic vertical offset for consistent netmon placement
function conky_network_voffset()
    local base_offset = 680  -- Your current voffset value
    local base_interfaces = 3  -- Expected number of interfaces for base_offset
    local line_height = 15  -- Approximate height per line in pixels
    
    if not check_connectivity() then
        return base_offset - (base_interfaces * line_height)  -- Minimal height for offline
    end
    
    local interfaces = get_all_interfaces()
    local actual_interfaces = math.min(#interfaces, 6)  -- Cap at 6 to prevent excessive height
    local interface_diff = actual_interfaces - base_interfaces
    
    -- Adjust offset: more interfaces = higher offset to push netmon down
    local adjusted_offset = base_offset + (interface_diff * line_height)
    return math.max(adjusted_offset, 100)  -- Minimum offset to prevent going off-screen
end

-- Get interface count for external use
function conky_network_interface_count()
    if not check_connectivity() then return 0 end
    local interfaces = get_all_interfaces()
    return #interfaces
end