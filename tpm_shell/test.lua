#!/usr/bin/lua
require("tpm_shell")

--Open a connection to the tpm and
--get a connection descriptor.
s = tpm_open("--tcti", "tabrmd")

-- Call tpm2_takeownership, arguments
-- supported will be the same as the
-- command line tool.
rc = takeownership(s, "-c")
if rc ~= 0 then
  tpm_close(s)
  os.exit (1)
end

rc = listpcrs(s)
if rc ~= 0 then
  tpm_close(s)
  os.exit (1)
end

-- Showcase an in-progress feature
-- where tool output can be returned
-- via a table.
rc, t = getrandom(s, "4")
if rc ~= 0 then
  tpm_close(s)
  os.exit (1)
end

print("\n\nRandom output via in memory return")
print(t["random"])
print("\n")

-- Close a connection with a tpm.
-- Calling anything using S after
-- tpm_close() is a user error
-- that results in undefined
-- behavior.
tpm_close(s)
