from numpy.lib.function_base import append
from util import User
from whotoo import WhoToo
from charm.toolbox.pairinggroup import PairingGroup
from time import time
import numpy as np

k = 4
n = 6
mac_k = 3
q = 2
group = PairingGroup('BN254')

# initialization with different m
m_vals = np.arange(200, 1001, 200)
times = []

for m in m_vals:


	valid_accusers = []
	for i in range(m):
		user = User(i, n)
		valid_accusers += [user]

	start = time()
	wt = WhoToo(group, k, n, q, mac_k, valid_accusers)
	end_init = time ()
	t = end_init-start
	times.append(t)

print('Users')
print(m_vals)
print(times)


# Different macs
times = []
mac_k_vals = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

valid_accusers = []
for i in range(100):
	user = User(i, n)
	valid_accusers += [user]

for mac in mac_k_vals:
	start = time()
	wt = WhoToo(group, k, n, q, mac, valid_accusers)
	end_init = time ()
	t = end_init-start
	times.append(t)

print('Macs')
print(mac_k_vals)
print(times)


# accs
wt = WhoToo(group, k, n, q, mac_k, valid_accusers)

times = []
persona = ["persona"+str(i) for i in range(100)]
for i in range(100):
	s = time()
	wt.accuse(valid_accusers[i], persona[i])
	e = time()
	t = e-s
	times.append(t)

print('Accs no quorum')
print(times)


times = []
persona = "persona"
for i in range(100):
	s = time()
	wt.accuse(valid_accusers[i], persona)
	e = time()
	t = e-s
	times.append(t)

print('Accs all quorum')
print(times)


# end = time()

# print("Init Time: ", end_init-start)
# print("Accs Submission Time: ", end-end_init)
# print("Total Time: ", end-start)

# print(last_acc)