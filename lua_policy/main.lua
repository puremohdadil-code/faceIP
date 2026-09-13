local policy = dofile("risk_policy.lua")

for line in io.lines() do
  local status, hostname, source = line:match("([^\t]*)\t([^\t]*)\t([^\t]*)")
  if status then
    local result = policy.assess({ status = status, hostname = hostname, source = source })
    print(string.format("%d\t%s", result.score, table.concat(result.reasons, ",")))
  end
end