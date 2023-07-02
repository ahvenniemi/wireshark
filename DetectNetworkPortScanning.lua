-- This script detects and alerts on network port scanning activity, such as SYN scans.

local synCount = 0
local output_file = "/path/to/desired/folder/XXXresults.txt"  -- Output file name

-- Register a listener to process each packet
local tap = Listener.new(nil, "tcp")

-- Function called for each packet
function tap.packet(pinfo, tvb)
    local tcp_flags = pinfo.tcp_flags

    -- Check the state of the SYN flag
    if tcp_flags.syn and not tcp_flags.ack then
        synCount = synCount + 1

        -- Check for SYN flood condition
        if synCount > 100 then
            -- Generate an alert
            local alert_msg = "Network SYN flood detected!"
            print(alert_msg)
            
            -- Write the alert to the output file
            local file = io.open(output_file, "a")
            file:write(alert_msg .. "\n")
            file:close()
        end
    end
end
