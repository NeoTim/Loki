#!/usr/bin/env python

import time
from loki_bindings import bf

obj = bf.ospf_md5_bf()
obj.pre_data = "0201002c0ac80f0d000000040000000200000010503fe764ffffff00000a100100000028ac1d51fe00000000".decode("hex")
obj.num_threads = 1
obj.hash_data = "f0a4c114225b5fe06362ef56639465e5".decode("hex")
obj.start()
while obj.running:
    time.sleep(0.01)
print "password: '%s'" % obj.pw
del obj

obj = bf.ospf_hmac_sha1_bf()
obj.pre_data = "0201002cac10000a00000000000000020000011454ee45b9ffffff00000a120100000028c0a86f0a00000000".decode("hex")
obj.hash_data = "53169aee3185a2ec8c26adce8b3677669b10da1c".decode("hex")
obj.start()
while obj.running:
    time.sleep(0.01)

print "password: '%s'" % obj.pw
del obj

obj = bf.tcpmd5_bf()
obj.pre_data = "45c000401c8340000106fd05c0a86f0ac0a86f14d05d00b32ff1bc6400000000b0024000c6360000020405b41312ed37a465e55a8155ac1c953ce087f7c30000"
obj.hash_data = "ed37a465e55a8155ac1c953ce087f7c3"
obj.start()
while obj.running:
    time.sleep(0.01)
    print obj.cur_pw

print "password: '%s'" % obj.pw
del obj


