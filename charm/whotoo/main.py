from util import User
from whotoo import WhoToo

k = 4
n = 6
mac_k = 3
q = 2

valid_accusers = []
for i in range(10):
	user = User(i, n)
	valid_accusers += [user]

wt = WhoToo(k, n, q, mac_k, valid_accusers)

wt.accuse(valid_accusers[0], 'persona1')
wt.accuse(valid_accusers[2], 'persona2')
wt.accuse(valid_accusers[1], 'persona1')
