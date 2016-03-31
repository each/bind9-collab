#!/bin/python
import sys
sys.path.insert(0, '..')
from isc import *

pp = policy.dnssec_policy()
# print the unmodified default and a generated zone policy
print pp.named_policy['default']
print pp.policy('example.com')

pp.load(sys.argv[1])
# now print the modfified default and generated zone policies
print pp.named_policy['default']
print pp.policy('example.com')
print pp.policy('example.org')
print pp.policy('example.net')

# print algorithm policies
print pp.alg_policy['RSASHA1']
print pp.alg_policy['DSA']

# print another named policy
print pp.named_policy['extra']
