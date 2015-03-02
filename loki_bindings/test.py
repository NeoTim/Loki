#!/usr/bin/env python

import time
from loki_bindings import bf

print "*** OSPF - MD5 ***"
obj = bf.ospf_md5_bf()
obj.pre_data = "0201002c0ac80f0d000000040000000200000010503fe764ffffff00000a100100000028ac1d51fe00000000".decode("hex")
obj.num_threads = 1
obj.hash_data = "f0a4c114225b5fe06362ef56639465e5".decode("hex")
obj.start()
while obj.running:
    time.sleep(0.01)
print "password: '%s'" % obj.pw
del obj

t0 = time.time()
print "*** OSPF - SHA1 ***"
obj = bf.ospf_hmac_sha1_bf()
obj.pre_data = "0201002cac10000a00000000000000020000011454ee45b9ffffff00000a120100000028c0a86f0a00000000".decode("hex")
obj.hash_data = "53169aee3185a2ec8c26adce8b3677669b10da1c".decode("hex")
obj.start()
while obj.running:
    time.sleep(0.01)
t1 = time.time()
print "password: '%s' in ~%ss" % (obj.pw, t1-t0)
del obj

t0 = time.time()
print "*** OSPF - SHA256 ***"
obj = bf.ospf_hmac_sha256_bf()
obj.pre_data = "0201002cac10000a00000000000000020000012054f4c8adffffff00000a120100000028c0a86f0a00000000".decode("hex")
obj.hash_data = "508a1abffb5b4554e1aa46eb053bca7105c3e8f6fece4c945f0a0020edb054ec".decode("hex")
obj.start()
while obj.running:
    time.sleep(0.01)
t1 = time.time()
print "password: '%s' in ~%ss" % (obj.pw, t1-t0)
del obj

t0 = time.time()
print "*** OSPF - SHA384 ***"
obj = bf.ospf_hmac_sha384_bf()
obj.pre_data = "0201002cac10000a00000000000000020000013054f4c8e4ffffff00000a120100000028c0a86f0a00000000".decode("hex")
obj.hash_data = "9dcf336773034f4ad8b0e19c52546ba72fd91d79d9416c9c1c4854002d3c0b5fc7c80fc1c4994ab9b6c48d9c6ac03587".decode("hex")
obj.start()
while obj.running:
    time.sleep(0.01)
t1 = time.time()
print "password: '%s' in ~%ss" % (obj.pw, t1-t0)
del obj

t0 = time.time()
print "*** OSPF - SHA512 ***"
obj = bf.ospf_hmac_sha512_bf()
obj.pre_data = "0201002cac10000a00000000000000020000014054f4c912ffffff00000a120100000028c0a86f0a00000000".decode("hex")
obj.hash_data = "4faa125881137ab3257ee9c8626d0ffa0c387c2e41a832d435afffc41d35881360fbe74442191a8aef201a4aad2689577a0c26a3cc5c681e72f09c297d16ba6a".decode("hex")
obj.start()
while obj.running:
    time.sleep(0.01)
t1 = time.time()
print "password: '%s' in ~%ss" % (obj.pw, t1-t0)
del obj

#~ print "*** OSPF - MD5 ***"
#~ obj = bf.tcpmd5_bf()
#~ obj.pre_data = "45c000401c8340000106fd05c0a86f0ac0a86f14d05d00b32ff1bc6400000000b0024000c6360000020405b41312ed37a465e55a8155ac1c953ce087f7c30000"
#~ obj.hash_data = "ed37a465e55a8155ac1c953ce087f7c3"
#~ obj.start()
#~ while obj.running:
    #~ time.sleep(0.01)
    #~ print obj.cur_pw
#~ 
#~ print "password: '%s'" % obj.pw
#~ del obj


