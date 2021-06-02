from hashlib import sha256
import charm.toolbox.symcrypto
from charm.toolbox.hash_module import *
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,order
#pair_prod
from charm.core.engine.util import objectToBytes,bytesToObject
from charm.toolbox.secretshare import *

# cambios en charm> 
# generate sharing tb devuelve coefficientes
# reconstruct sharings se cambia el 0 pq tiene q ser pairing element

class WhoToo():

	group = None
	g = None
	h = None

	el_gamal = None
	sec_share = None
	dist_bbs = None
	set_operations = None

	def __init__(self, k, n):
		self.group = PairingGroup('BN254')
		self.el_gamal = ElGamal(self.group)
		(pkeg, skeg) = self.el_gamal.gen_keys()
		self.g = pkeg['g']
		self.h = pkeg['h']
		self.sec_share = SecShare(self.group, self.g, self.h, k, n, self.el_gamal)


	



	


class BBS():
	group = None
	g1 = None
	g2 = None
	u = None
	v = None
	w = None
	h = None

	def __init__(self, group, g1, h):
		self.group = group
		self.u = g
		self.v = h
		self.g1 = self.group.random(G1)
		self.g2 = self.group.random(G2)
		self.w = self.group.random(G2)
		self.h = Hash(pairingElement=self.group)

	def phi(self, t1, t2, t3, c1, c2):
		tt1 = self.u ** t1
		tt2 = (c1 ** t2) * (self.u ** (-1 * t3))
		tt3 = (self.group.pair_prod(c2, self.g2) ** t2) * (self.group.pair_prod(self.v, self.w) ** (-1 * t1)) * (self.group.pair_prod(self.v, self.g2) ** (-1 * t3))
		return (tt1, tt2, tt3)

	def sign(self, sku, m):
		(R, alpha) = sku
		a = self.group.random(ZR)
		cR = ( self.u ** a, ( self.v ** a ) * R )
		c1, c2 = cR
		r1 = self.group.random(ZR)
		r2 = self.group.random(ZR)
		r3 = self.group.random(ZR)
		calc = self.phi(r1, r2, r3, c1, c2)

		# pasar cosas a bytes antes de hash maybe

		m_bytes = objectToBytes(m, self.group)
		cR_bytes = objectToBytes(cR, self.group)
		calc_bytes = objectToBytes(calc, self.group)
		z = self.h.hashToZr(m_bytes, cR_bytes, calc_bytes)

		t1 = z*a
		t2 = z*alpha
		t = (z * a, z * alpha, z * a * alpha)
		s = (r1 + t[0], r2 + t[1], r3 + t[2])

		sigma = (z, s)

		return (cR, sigma)

	def verify(self, m, cR, sigma):
		(c1, c2) = cR
		(z, s) = sigma
		(r1, r2, r3) = s

		calc = self.phi(r1, r2, r3, c1, c2)

		t1 = c1 ** z
		t2 = 1
		t3 = (self.group.pair_prod(self.g1, self.g2) / self.group.pair_prod(c2, self.w)) ** z

		rp = (calc[0]/t1, calc[1]/t2, calc[2]/t3)

		m_bytes = objectToBytes(m, self.group)
		cR_bytes = objectToBytes(cR, self.group)
		rp_bytes = objectToBytes(rp, self.group)

		hcalc = self.h.hashToZr(m_bytes, cR_bytes, rp_bytes)

		return z == hcalc












	

N = 3
K = 3



for i in range(1, N+1):
	s = Server(i)
	servers += [s]

el_gamal = ElGamal(GROUP)

g = GROUP.random(G1)
pedersen_h = GROUP.random(G1)
sec_share = SecShare(GROUP, g, pedersen_h, K, N, el_gamal)

g2 = GROUP.random(G2)
pedersen_h2 = GROUP.random(G2)
sec_share_g2 = SecShare(GROUP, g2, pedersen_h2, K, N, el_gamal)




## INITIALIZE
valid_accusers = VALID_ACCUSERS

#DistBBs.Setup
servers, h = sec_share_gen(servers, GROUP, g, sec_share, 'x_share_')
servers, omega = sec_share_gen(servers, GROUP, g2, sec_share_g2, 'gamma_share_')

bbs = BBS(GROUP, g, h)

pkeg = {'g': g, 'h': h}
el_gamal.pkeg = pkeg
sec_share.h = h


identity_map = {}

for u in valid_accusers:
	u_id = u.get('idx')

	#DistBBS.UserKeyIssue
	servers, R = gen_inv_temp(servers, GROUP, g, sec_share, 'gammap_share_')
	u.R = R

	for p in servers:
		p_id = p.get('idx')
		gamma_i, r = p.get('gamma_share_' + str(p_id))
		gammap_i, r = p.get('gammap_share_' + str(p_id))
		alpha_i = sec_share.sub(gammap_i, gamma_i)

		u.save('alpha_share_' + str(p_id) + str(u_id), alpha_i)


	alpha_shares = [0]

	for i in range(1, N+1):
		ai = u.get('alpha_share_' + str(i) + str(u_id))
		alpha_shares += [ai]

	y = {GROUP.init(ZR, i): alpha_shares[i] for i in range(1, N+1)}
	alpha = sec_share.reconstruct(y)

	u.alpha = alpha


	identity_map[R] = u

a = GROUP.random(ZR)
S = [el_gamal.enc(a, g ** 0)]

ra = GROUP.random(ZR)
eg0 = el_gamal.enc(ra, g ** 0)

accusations = set()

######## testing ######
shares = [0]
for p in servers:
	p_id = p.get('idx')
	var_name = 'x_share_' + str(p_id)
	s = p.get(var_name)
	shares += [s]

group = GROUP
y = {group.init(ZR, 1):shares[1][0], group.init(ZR, 2):shares[2][0], group.init(ZR, 3):shares[3][0]}
x = sec_share.reconstruct(y)

el_gamal.skeg = {'x': x}

###########################

## PREPARE ACC
u = valid_accusers[2]

D = 'acusado_id'
rD = GROUP.random(ZR)
cD = el_gamal.enc_string(rD, D)
cDd = {'c1': cD[0], 'c2': cD[1]}
h = Hash(pairingElement=GROUP)
s = h.hashToZr(D)
w, v, e0, r = sec_share.share_encode(s)
es = {'c1': e0, 'c2': v[0]}

accs = [0]
for i in range(1, N+1):
	m = (cD, w[i], v, e0)
	sku = (u.R, u.alpha)

	# cR, sigma = bbs.sign(sku, m)
	a = GROUP.random(ZR)
	cR = el_gamal.enc(a, R)
	sigma = (GROUP.random(ZR, 2))

	pi0 = el_gamal.prove(es, r, (cR, sigma))
	pi1 = el_gamal.prove(cDd, rD, (cR, sigma))

	acc = (cR, cD, w[i], v, e0, sigma, pi0, pi1)
	accs += [acc]


## ACCUSE

## VERIFY ACC

for p in servers:
	p_id = p.get('idx')
	cR, cD, wi, v, e0, sigma, pi0, pi1 = accs[i]
	es = {'c1': e0, 'c2': v[0]}
	m = (cD, wi, v, e0)
	cD = {'c1': cD[0], 'c2': cD[1]}

	ver = []
	vt = el_gamal.verify(pi0, es, (cR, sigma))
	ver += [(vt, 'pi0')]
	vt = el_gamal.verify(pi1, cD, (cR, sigma))
	ver += [(vt, 'pi1')]
	# vt = bbs.verify(m, cR, sigma)
	# v += [(vt, 'bbs')]
	si, ri = wi
	vt = sec_share.verify(si, ri, v, p_id)

	for (vi, ni) in ver:
		if not vi:
			print('Failed to verify ' + ni)


###### DUPLICATES #####
# ORIGINAL

h = Hash(pairingElement=GROUP)

def e_prove(c1, c2, a, r, h):
	a1, a2 = a
	k = GROUP.random(ZR)
	b1 = c1 ** k
	b2 = c2 ** k
	a1_bytes = objectToBytes(a1, GROUP)
	a2_bytes = objectToBytes(a2, GROUP)
	b1_bytes = objectToBytes(b1, GROUP)
	b2_bytes = objectToBytes(b2, GROUP)
	c1_bytes = objectToBytes(c1, GROUP)
	c2_bytes = objectToBytes(c2, GROUP)
	alpha = h.hashToZr(a1_bytes, a2_bytes, b1_bytes, b2_bytes, c1_bytes, c2_bytes)
	beta = alpha * k + r
	return (beta, b1, b2)


def e_verify(c1, c2, pi, a, h):
	beta, b1, b2 = pi
	a1, a2 = a
	a1_bytes = objectToBytes(a1, GROUP)
	a2_bytes = objectToBytes(a2, GROUP)
	b1_bytes = objectToBytes(b1, GROUP)
	b2_bytes = objectToBytes(b2, GROUP)
	c1_bytes = objectToBytes(c1, GROUP)
	c2_bytes = objectToBytes(c2, GROUP)
	alpha = h.hashToZr(a1_bytes, a2_bytes, b1_bytes, b2_bytes, c1_bytes, c2_bytes)
	ver1 = c1 ** beta == a1 * (b1 ** alpha)
	ver2 = c2 ** beta == a2 * (b2 ** alpha)
	res = ver1 and ver2
	return res


def dist_dec(c1, c2):
	di = SecShare.Exp(c1, x)
	d = SecShare.Reconstruc(di)
	return c2/d

def msgrand(c):
	c1, c2 = c
	for p in servers:
		p_id = p.get('idx')
		ri = GROUP.random(ZR)
		ai = (c1 ** ri, c2 ** ri)
		pii = e_prove(c1, c2, ai, ri)
		var_name = 'ai_' + str(p_id)
		BROADCAST[var_name] = ai
		var_name = 'pii_' + str(p_id)
		BROADCAST[var_name] = pii

	for p in servers:
		p_id = p.get('idx')

		for s in servers:
			s_id = s.get('idx')
			var_name = 'ai_' + str(s_id)
			asi = BROADCAST[var_name]
			var_name = 'pii_' + str(s_id)
			pisi = BROADCAST[var_name]
			ver = e_verify(c1, c2, pisi, asi)
			if not ver:
				print('Server ' + str(p_id) + ' failed to verify share from server ' + str(s_id) + ' during Equal')

	a1 = 1
	a2 = 1
	for i in range(1, N+1):
		var_name = 'ai_' + str(i)
		ai = BROADCAST[var_name]
		ai1, ai2 = ai
		a1 *= ai1
		a2 += ai2

	cp = (a1, a2)
	m = dist_dec(cp)






def equalsfunc(skeg, ca, cb):
	c1a, c2a = ca
	c1b, b2b = cb
	c1 = c1a / c1b
	c2 = c2a / c2b
	c = (c1, c2)
	return msgrand(c)


servers = []
accusations = [(cr, es, cd) for i in range(10)]
esp = 0
crp = 0
for acc in accusations:





def set_union(S, servers, name_share)
	for p in servers:
		p_id = p.get('idx')
		sh = p.get(name_share + str(p_id))
		eg = [eg0] + S

		for ef in S:
			ehi = sec_share.expRR(ef, sh)


		






	print('\n\nR ', u.R)
	print('\ndec cR ', el_gamal.dec(cR))
	pi0 = el_gamal.prove(es, r, )


print('R ', u.R)
print('s ', s)
print('g^s ', g ** s)
print('D', D)

print('dec es ', el_gamal.dec(es))
print('dec cD ', el_gamal.dec_string(cD))



servers, res = gen_inv_temp(servers, GROUP, g, sec_share, 'gammap_share_')

shares = [0]
for p in servers:
	p_id = p.get('idx')
	var_name = 'gammap_share_' + str(p_id)
	s = p.get(var_name)
	shares += [s]

print(type(shares[1]))

group = GROUP
y = {group.init(ZR, 1):shares[1][0], group.init(ZR, 2):shares[2][0], group.init(ZR, 3):shares[3][0]}
x = sec_share.reconstruct(y)


print('x: ', x)
print('res: ', res)
val = g ** (x ** -1)
print('gx-1: ', val)

