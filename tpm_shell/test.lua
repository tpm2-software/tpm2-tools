#!/usr/bin/lua
require("tpm_shell")
--print(square(1.414213598))
--print(cube(5))

s = sapi_init("tabrmd")

print(s)

take_ownership(s, "-c")

