-- Define the IP address range to scan
local start_ip = "10.0.0.1"
local end_ip = "10.0.0.255"
local output_file = "/path/to/desired/folder/MaliciousNetworkTraffic_results.txt"

-- Register a listener to process each packet
local tap = Listener.new(nil, "")

-- Function called for each packet
function tap.packet(pinfo, tvb)
    local src_ip = tostring(pinfo.src)
    local dst_ip = tostring(pinfo.dst)

    -- Check if the source or destination IP falls within the defined range
    if ip_in_range(src_ip, start_ip, end_ip) or ip_in_range(dst_ip, start_ip, end_ip) then
        -- Generate an alert
        local alert_msg = "Malicious network traffic detected: " .. src_ip .. " -> " .. dst_ip
        print(alert_msg)
        
        -- Write the alert to the output file
        local file = io.open(output_file, "a")
        file:write(alert_msg .. "\n")
        file:close()
    end
end

-- Helper function to check if an IP address falls within a range
function ip_in_range(ip, start_range, end_range)
    local start_num = ip_to_number(start_range)
    local end_num = ip_to_number(end_range)
    local ip_num = ip_to_number(ip)
    
    return ip_num >= start_num and ip_num <= end_num
end

-- Helper function to convert an IP address to a number
function ip_to_number(ip)
    local ip_octets = {}
    for octet in string.gmatch(ip, "%d+") do
        table.insert(ip_octets, tonumber(octet))
    end
    
    return ip_octets[1] * 16777216 + ip_octets[2] * 65536 + ip_octets[3] * 256 + ip_octets[4]
end
