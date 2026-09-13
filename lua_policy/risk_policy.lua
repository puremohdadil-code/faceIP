local M = {}

function M.assess(device)
  local score = 0
  local reasons = {}
  if device.status == "new" then
    score = score + 35
    table.insert(reasons, "device_seen_for_the_first_time")
  end
  if device.source == "arp" and (device.hostname == nil or device.hostname == "") then
    score = score + 10
    table.insert(reasons, "hostname_not_resolved")
  end
  return { score = math.min(score, 100), reasons = reasons }
end

return M
