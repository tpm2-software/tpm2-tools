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

-- Close a connection with a tpm.
-- Calling anything using S after
-- tpm_close() is a user error
-- that results in undefined
-- behavior.
tpm_close(s)
