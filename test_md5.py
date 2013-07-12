import home_crypto.md5 as md5

import sys

input = sys.argv[1]

print sys.argv[1], "hashes to", md5.reference_implementation(input)

print "home rolled implementation says:", md5.md5(input)
