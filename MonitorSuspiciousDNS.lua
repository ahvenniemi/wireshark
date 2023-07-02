-- This script monitors DNS requests and identifies potentially suspicious queries.

local output_file = "/path/to/desired/folder/MonitorSuspiciousDNSresults.txt"  -- Output file name

-- Register a listener to process each DNS packet
local tap = Listener.new(nil, "dns")

-- Function called for each packet
function tap.packet(pinfo, tvb)
    local dns_qry_name = tostring(pinfo.qry_name)

    -- Check for suspicious DNS queries
    if string.match(dns_qry_name, "%.xyz$") then
        -- Generate an alert
        local alert_msg = "Suspicious DNS query detected: " .. dns_qry_name
        print(alert_msg)
        
        -- Write the alert to the output file
        local file = io.open(output_file, "a")
        file:write(alert_msg .. "\n")
        file:close()
    end
end
