from typing import SupportsAbs
from charm.core.engine.util import objectToBytes
import unittest
from util import *
from charm.toolbox.pairinggroup import PairingGroup,G1,ZR,G2
from elgamal import ElGamal
from secshare import SecShare
from bbs import BBS
from ibe import DistIBE
from dimac import Dimac
from privatepoly import PrivatePoly
from wtset import PrivateMultiset
from whotoo import WhoToo

group = PairingGroup('BN254')
eg = ElGamal(group)
pkeg, skeg = eg.gen_keys()
k = 4
n = 6
g2 = group.random(G2)
sec_share = SecShare(group, pkeg['g'], g2, k, n, eg)
sec_share.h = pkeg['h']

gamma = group.random(ZR)
w, v, e0, rr = sec_share.share_encode(gamma)

skdiprf = group.random(ZR)
wdiprf, v, e0, rr = sec_share.share_encode(skdiprf)
skibe = group.random(ZR)
wibe, v, e0, rr = sec_share.share_encode(skibe)
gp = pkeg['g'] ** skibe

r = group.random(ZR)
a = group.random(ZR)
b = group.random(ZR)
c = a * b
wa, v = sec_share.gen_pedersen(a, r)
wb, v = sec_share.gen_pedersen(b, r)
wc, v = sec_share.gen_pedersen(c, r)


servers = []
for i in range(1, n+1):
	ser = Server(i, n)
	ser.beaver = (wa[i][0], wb[i][0], wc[i][0])
	servers += [ser]

for p in servers:
	pid = p.id
	p.skbbs_share = w[pid][0]
	p.skdiprf_share = wdiprf[pid][0]
	p.skibe_share = wibe[pid][0]



pkbbs = g2 ** gamma
bbs = BBS(group, pkeg['g'], g2, pkeg['h'], pkbbs, sec_share)

ibe = DistIBE(group, pkeg['g'], g2, gp, sec_share)
dimac = Dimac(sec_share)

poly = PrivatePoly(sec_share, eg, pkeg)
mset = PrivateMultiset(sec_share, eg, pkeg)

class TestWhoToo(unittest.TestCase):

	def test_el_gamal_basic(self):
		m1 = group.random(G1)
		c1 = eg.enc(pkeg, m1)
		d1 = eg.dec(skeg, c1)
		self.assertEqual(m1, d1)

	def test_el_gamal_str(self):
		m1 = 'AccusedPersonName'
		c1 = eg.enc_string(pkeg, m1)
		d1 = eg.dec_string(skeg, c1)
		self.assertEqual(m1, d1)

	def test_el_gamal_proof(self):
		a = group.random(ZR)
		rho = group.random(ZR)
		m1 = group.random(G1)
		c1 = eg.enc(pkeg, m1, a)
		pi = eg.prove(pkeg, c1, a, rho)
		ver = eg.verify(pkeg, pi, c1, rho)
		self.assertTrue(ver)

	def test_el_gamal_proof_wrong(self):
		a = group.random(ZR)
		rho = group.random(ZR)
		m1 = group.random(G1)
		c1 = eg.enc(pkeg, m1)
		pi = eg.prove(pkeg, c1, a, rho)
		ver = eg.verify(pkeg, pi, c1, rho)
		self.assertFalse(ver)

	def test_el_gamal_proof_str_wrong(self):
		a = group.random(ZR)
		rho = group.random(ZR)
		m1 = 'SomeAccusedPerson'
		c1 = eg.enc_string(pkeg, m1)
		pi = eg.prove(pkeg, c1, a, rho)
		ver = eg.verify(pkeg, pi, c1, rho)
		self.assertFalse(ver)

	def test_pedersen_share_verify(self):
		s = group.random(ZR)
		r = group.random(ZR)
		w, v = sec_share.gen_pedersen(s, r)
		
		ver  = True

		for i in range(1, len(w)):
			(si, ri) = w[i]
			ver_i = sec_share.verify_pedersen(si, ri, v, i)
			ver = ver and ver_i

		self.assertTrue(ver)

	def test_pedersen_share_reconstruct(self):
		s = group.random(ZR)
		r = group.random(ZR)
		w, v = sec_share.gen_pedersen(s, r)

		s_shares = {group.init(ZR, i):w[i][0] for i in range(1, len(w))}
		reconstructed_s = sec_share.reconstruct(s_shares)

		self.assertEqual(s, reconstructed_s)

	def test_pedersen_share_reconstruct_k(self):
		s = group.random(ZR)
		r = group.random(ZR)
		w, v = sec_share.gen_pedersen(s, r)

		s_shares = {group.init(ZR, i):w[i][0] for i in range(1, k+1)}
		reconstructed_s = sec_share.reconstruct(s_shares)

		self.assertEqual(s, reconstructed_s)

	def test_zklog_proof(self):
		r = group.random(ZR)
		b1 = group.random(G1)
		b2 = group.random(G1)
		b1r = b1 ** r
		b2r = b2 ** r
		a, c, t = zklogeq(group, b1, b2, r)
		ver = zklogeq_verify(b1, b2, b1r, b2r, a, c, t)

		self.assertTrue(ver)


	def test_zklog_proof_wrong(self):
		r = group.random(ZR)
		rw = group.random(ZR)
		b1 = group.random(G1)
		b2 = group.random(G1)
		b1r = b1 ** r
		b2r = b2 ** rw
		a, c, t = zklogeq(group, b1, b2, r)
		ver = zklogeq_verify(b1, b2, b1r, b2r, a, c, t)

		self.assertFalse(ver)

	def test_secshare_exp(self):
		s = group.random(ZR)
		r = group.random(ZR)
		b = group.random(G1)
		w, v = sec_share.gen_pedersen(s, r)

		for i in range(1, n+1):
			ser = servers[i-1]
			ser.temp1 = w[i][0]

		bs = sec_share.exp(servers, b)

		self.assertEqual(b ** s, bs)

	# def test_secshare_mult(self):
	# 	s = group.random(ZR)
	# 	r = group.random(ZR)
	# 	w, v = sec_share.gen_pedersen(s, r)

	# 	for i in range(1, n+1):
	# 		ser = servers[i-1]
	# 		ser.temp1 = w[i][0]
	# 		ser.temp2 = w[i][1]

	# 	servs = sec_share.mult(servers)
	# 	m_shares = {group.init(ZR, i):servs[i-1].temp3 for i in range(1, n+1)}
	# 	reconstructed_m = sec_share.reconstruct(m_shares)

	# 	self.assertEqual(s * r, reconstructed_m)

	def test_mult_beaver(self):
		# r = group.random(ZR)
		# a = group.random(ZR)
		# b = group.random(ZR)
		# c = a * b
		# wa, v = sec_share.gen_pedersen(a, r)
		# wb, v = sec_share.gen_pedersen(b, r)
		# wc, v = sec_share.gen_pedersen(c, r)

		x = group.random(ZR)
		y = group.random(ZR)
		wx, v = sec_share.gen_pedersen(x, r)
		wy, v = sec_share.gen_pedersen(y, r)

		z = x * y

		for p in servers:
			pid = p.id
			# p.beaver = (wa[pid][0], wb[pid][0], wc[pid][0])
			p.temp1 = wx[pid][0]
			p.temp2 = wy[pid][0]


		servs = sec_share.mult(servers)

		z_shares = {}
		for p in servs:
			dk = group.init(ZR, p.id)
			z_shares[dk] = p.temp3

		z_rec = sec_share.reconstruct(z_shares)

		self.assertEqual(z, z_rec)


	def test_check_consistent(self):
		s = group.random(ZR)
		w, v, e0, r = sec_share.share_encode(s)

		for p in servers:
			pid = p.id
			p.temp1 = w[pid][1]

		ver = sec_share.check_consistent(servers, e0)
		self.assertTrue(ver)


	def test_check_consistent_wrong(self):
		s = group.random(ZR)
		w, v, e0, r = sec_share.share_encode(s)

		for p in servers:
			pid = p.id
			p.temp1 = w[pid][1]

		ver = sec_share.check_consistent(servers, pkeg['g'] ** s)
		self.assertFalse(ver)

	def test_expRR(self):
		s = group.random(ZR)
		w, v, e0, r = sec_share.share_encode(s)

		for p in servers:
			pid = p.id
			p.temp1 = w[pid][0]

		e = eg.enc(pkeg, pkeg['g'] ** r)
		eRR = sec_share.expRR(servers, e)
		dec = eg.dec(skeg, eRR)

		self.assertEqual(dec, pkeg['g'] ** (r * s))


	def test_feldman(self):
		s = group.random(ZR)
		r = group.random(ZR)
		w, v, vf = sec_share.gen_pedersen(s, r, feldman=True)
		
		ver  = True

		for i in range(1, len(w)):
			(si, ri) = w[i]
			ver_i = sec_share.verify_feldman(si, vf, i)
			ver = ver and ver_i

		self.assertTrue(ver)


	def test_sec_share_geng(self):
		servs, h = sec_share.geng(servers)

		x_shares = {}
		
		for p in servs:
			dk = group.init(ZR, p.id)
			x_shares[dk] = p.temp2

		x = sec_share.reconstruct(x_shares)

		self.assertTrue(h, pkeg['g'] ** x)

	def test_sec_share_inv(self):
		s = group.random(ZR)
		w, v, e0, r = sec_share.share_encode(s)

		for p in servers:
			pid = p.id
			p.temp1 = w[pid][0]

		servs = sec_share.invert(servers)

		x_shares = {}
		
		for p in servs:
			dk = group.init(ZR, p.id)
			x_shares[dk] = p.temp3

		x = sec_share.reconstruct(x_shares)

		self.assertEqual(x, s ** -1)

	def test_gen_zero(self):
		servs = sec_share.gen_zero(servers)

		x_shares = {}
		
		for p in servs:
			dk = group.init(ZR, p.id)
			x_shares[dk] = p.temp2

		x = sec_share.reconstruct(x_shares)

		self.assertEqual(x, group.init(ZR, 0))

	def test_gen_inv(self):
		servs, res = sec_share.gen_inv(servers)

		x_shares = {}
		
		for p in servs:
			dk = group.init(ZR, p.id)
			x_shares[dk] = p.temp4

		x = sec_share.reconstruct(x_shares)
		gx = pkeg['g'] ** (x ** -1)
		self.assertEqual(res, gx)

	def test_dist_dec(self):
		m = group.random(G1)
		c = eg.enc(pkeg, m)

		w, v, e0, r = sec_share.share_encode(skeg)
		for p in servers:
			pid = p.id
			p.skeg_share = w[pid][0]

		dec = sec_share.dist_dec(servers, c)

		self.assertEqual(m, dec)	


	def test_dist_dec_str(self):
		m = 'SomeString'
		c = eg.enc_string(pkeg, m)

		w, v, e0, r = sec_share.share_encode(skeg)
		for p in servers:
			pid = p.id
			p.skeg_share = w[pid][0]

		dec = sec_share.dist_dec_str(servers, c)

		self.assertEqual(m, dec.decode("utf-8"))	


	def test_bbs_keyissue(self):
		user = User(1, n)
		servs, r = bbs.key_issue(servers, user)

		gamma_shares = {}
		for p in servs:
			dk = group.init(ZR, p.id)
			gamma_shares[dk] = p.skbbs_share

		gamma = sec_share.reconstruct(gamma_shares)
		alpha = user.alpha

		expected = pkeg['g'] ** ((alpha + gamma) ** -1)
		self.assertEqual(r, expected)


	def test_bbs_sign(self):
		user = User(1, n)

		servs, r = bbs.key_issue(servers, user)

		m1 = group.random(ZR)
		m2 = group.random(ZR)
		m3 = group.random(ZR)
		m4 = group.random(ZR)

		m = (m1, m2, m3, m4)
		sku = (user.R, user.alpha)
		cR, sigma = bbs.sign(sku, m)

		ver = bbs.verify(m, cR, sigma)

		self.assertTrue(ver)

	def test_bbs_sign_wrong(self):
		user = User(1, n)

		servs, r = bbs.key_issue(servers, user)

		m1 = group.random(ZR)
		m2 = group.random(ZR)
		m3 = group.random(ZR)
		m4 = group.random(ZR)

		m = (m1, m2, m3, m4)
		sku = (user.R, user.alpha)
		cR, sigma = bbs.sign(sku, m)

		m4 = group.random(ZR)
		m = (m1, m2, m3, m4)

		ver = bbs.verify(m, cR, sigma)

		self.assertFalse(ver)

	def test_multexp(self):
		a = group.random(ZR)
		b = group.random(ZR)
		wa, v, e0, r = sec_share.share_encode(a)
		wb, v, e0, r = sec_share.share_encode(b)

		for p in servers:
			pid = p.id
			p.temp4 = wa[pid][0]
			p.temp5 = wb[pid][0]

		b1 = group.random(G1)
		b2 = group.random(G1)

		res = sec_share.multexp(servers, b1, b2)
		expected = (b1 ** a) * (b2 ** b)

		self.assertEqual(expected, res)

	def test_diprf_alldas(self):
		x = group.random(ZR)
		w, v, e0, rr = sec_share.share_encode(x)

		for p in servers:
			pid = p.id
			p.temp1 = w[pid][0]

		expp = (skdiprf + x) ** -1
		res = sec_share.diprf(servers)
		expected = group.pair_prod(pkeg['g'], g2) ** expp

		self.assertEqual(expected, res)


	def test_diprf_user(self):
		user = User(1, n)

		x = group.random(ZR)
		w, v, e0, rr = sec_share.share_encode(x)

		for p in servers:
			pid = p.id
			p.temp1 = w[pid][0]

		expp = (skdiprf + x) ** -1
		user = sec_share.diprf(servers, recipient=user)

		expected = group.pair_prod(pkeg['g'], g2) ** expp

		res = 1
		for i in range(1, n+1):
			pid = group.init(ZR, i)
			res *= (user.da_shares[i-1] ** sec_share.coeffs[pid])

		self.assertEqual(expected, res)

	def test_dimac_tag(self):
		user = User(1, n)
		tau = group.random(ZR)
		(j, dj) = dimac.tag(servers, tau, user)

		expected = group.pair_prod(pkeg['g'], g2) ** ((skdiprf + tau + j) ** -1)
		self.assertEqual(expected, dj)

	def test_dimac_verify(self):
		user = User(1, n)
		tau = group.random(ZR)
		(j, dj) = dimac.tag(servers, tau, user)

		w, v, e0, rr = sec_share.share_encode(tau)
		for p in servers:
			pid = p.id
			p.temp1 = w[pid][0]


		ver = dimac.verify(servers, dj, j)
		self.assertTrue(ver)

	def test_dimac_verify_wrong(self):
		user = User(1, n)
		tau = group.random(ZR)
		(j, dj) = dimac.tag(servers, tau, user)

		tau = group.random(ZR)
		w, v, e0, rr = sec_share.share_encode(tau)
		for p in servers:
			pid = p.id
			p.temp1 = w[pid][0]


		ver = dimac.verify(servers, dj, j)
		self.assertFalse(ver)

	def test_ibe(self):
		id = group.random(ZR)
		w, v, e0, rr = sec_share.share_encode(id)
		for p in servers:
			pid = p.id
			p.temp1 = w[pid][0]

		c = ibe.enc(servers)
		k = ibe.key_gen(servers, id)
		dec = ibe.dec(k, c)

		self.assertTrue(dec)

	def test_ibe_wrong(self):
		id = group.random(ZR)
		id2 = group.random(ZR)
		w, v, e0, rr = sec_share.share_encode(id)
		for p in servers:
			pid = p.id
			p.temp1 = w[pid][0]

		c = ibe.enc(servers)
		k = ibe.key_gen(servers, id2)
		dec = ibe.dec(k, c)

		self.assertFalse(dec)

	def test_poly_subtract(self):
		d = 5
		f = []
		g = []
		eF = []
		eG = []
		for i in range(d):
			Fi = group.random(ZR)
			f += [Fi]
			Gi = group.random(ZR)
			g += [Gi]
			eFi = eg.enc(pkeg, pkeg['g'] ** Fi)
			eGi = eg.enc(pkeg, pkeg['g'] ** Gi)
			eF += [eFi]
			eG += [eGi]

		eH = poly.subtract(eF, eG)
		sub = True
		for i in range(d):
			Hi = eg.dec(skeg, eH[i])
			sub = sub and (Hi == pkeg['g'] ** (f[i]-g[i]))

		self.assertTrue(sub)

	def test_poly_diff(self):
		d = 5
		f = []
		eF = []
		for i in range(d):
			Fi = group.random(ZR)
			f += [Fi]
			eFi = eg.enc(pkeg, pkeg['g'] ** Fi)
			eF += [eFi]

		eH = poly.differentiate(eF, 2)
		diff = True
		for i in range(3):
			Hi = eg.dec(skeg, eH[i])
			diff = diff and (Hi == pkeg['g'] ** ((i+1)*(i+2)*f[i+2]))

		self.assertTrue(diff)

	def test_poly_mult(self):
		d = 5
		f = []
		r = []
		eF = []
		for i in range(d):
			Fi = group.random(ZR)
			f += [Fi]
			Ri = group.random(ZR)
			r += [Ri]
			eFi = eg.enc(pkeg, pkeg['g'] ** Fi)
			eF += [eFi]

		eG = poly.multiply(eF, r)

		fr = [0]*9
		for i in range(0, 5):
			for j in range(0, 5):
				fr[i+j] = fr[i+j] + (f[i] * r[j])


		mult = True
		for i in range(0, 9):
			Gi = eg.dec(skeg, eG[i])
			mult = mult and ((pkeg['g'] ** fr[i]) == Gi)

		self.assertTrue(mult)

		
	def test_poly_mult_linear(self):
		d = 5
		f = []
		eF = []
		for i in range(d):
			Fi = group.random(ZR)
			f += [Fi]
			eFi = eg.enc(pkeg, pkeg['g'] ** Fi)
			eF += [eFi]

		s = group.random(ZR)
		w, v, e0, rr = sec_share.share_encode(s)
		for p in servers:
			pid = p.id
			p.temp1 = w[pid][0]


		fs = [-1 * f[0]*s] + [f[i-1]-f[i]*s for i in range(1, 5)] + [f[4]]
		eG = poly.multiply_linear(servers, eF)
		mult = True
		for i in range(len(eG)):
			Gi = eg.dec(skeg, eG[i])
			mult = mult and (Gi == pkeg['g'] ** fs[i])

		self.assertTrue(mult)


	def test_mr_prove_ver(self):
		m = group.random(ZR)
		c1, c2 = eg.enc(pkeg, m)
		r = group.random(ZR)
		a1 = c1 ** r
		a2 = c2 ** r
		pi = mr_prove(group, c1, c2, a1, a2, r)
		ver = mr_verify(group, c1, c2, pi, a1, a2)

		self.assertTrue(ver)

	def test_mr_prove_ver_wrong(self):
		m = group.random(ZR)
		c1, c2 = eg.enc(pkeg, m)
		r = group.random(ZR)
		r2 = group.random(ZR)
		a1 = c1 ** r
		a2 = c2 ** r
		pi = mr_prove(group, c1, c2, a1, a2, r2)
		ver = mr_verify(group, c1, c2, pi, a1, a2)

		self.assertFalse(ver)

	def test_msgrand(self):
		m = pkeg['g'] ** 0
		c = eg.enc(pkeg, m)
		val = sec_share.msg_rand(servers, c)
		self.assertEqual(val, m)

	def test_msgrand_not_zero(self):
		m = group.random(ZR)
		c = eg.enc(pkeg, m)
		val = sec_share.msg_rand(servers, c)
		self.assertNotEqual(val, m)


	def test_zerotest(self):
		s1 = group.random(ZR)
		s2 = group.random(ZR)
		eF = [eg.enc(pkeg, pkeg['g'])]

		w1, v, e0, rr = sec_share.share_encode(s1)
		w2, v, e0, rr = sec_share.share_encode(s2)
		for p in servers:
			pid = p.id
			p.temp1 = w1[pid][0]
		eF = poly.multiply_linear(servers, eF)
		
		for p in servers:
			pid = p.id
			p.temp1 = w2[pid][0]
		eF = poly.multiply_linear(servers, eF)


		for p in servers:
			pid = p.id
			p.temp1 = w1[pid][0]
		zerotest = poly.zero_test(servers, eF)

		self.assertTrue(zerotest)


	def test_zerotest_notzero(self):
		s1 = group.random(ZR)
		s2 = group.random(ZR)
		eF = [eg.enc(pkeg, pkeg['g'])]

		w1, v, e0, rr = sec_share.share_encode(s1)
		w2, v, e0, rr = sec_share.share_encode(s2)
		for p in servers:
			pid = p.id
			p.temp1 = w1[pid][0]
		eF = poly.multiply_linear(servers, eF)
		
		for p in servers:
			pid = p.id
			p.temp1 = w2[pid][0]
		eF = poly.multiply_linear(servers, eF)

		s3 = group.random(ZR)
		w3, v, e0, rr = sec_share.share_encode(s3)
		for p in servers:
			pid = p.id
			p.temp1 = w3[pid][0]

		zerotest = poly.zero_test(servers, eF)

		self.assertFalse(zerotest)

	def test_quorum(self):
		eF = mset.initialize()
		
		s1 = group.random(ZR)
		s2 = group.random(ZR)
		s3 = group.random(ZR)
		s4 = group.random(ZR)

		w1, v, e0, rr = sec_share.share_encode(s1)
		w2, v, e0, rr = sec_share.share_encode(s2)
		w3, v, e0, rr = sec_share.share_encode(s3)
		w4, v, e0, rr = sec_share.share_encode(s4)
		for j in range(3): # agregamos s1 3 veces
			for p in servers:
				pid = p.id
				p.temp1 = w1[pid][0]
			eF = poly.multiply_linear(servers, eF)
		
		for p in servers:
			pid = p.id
			p.temp1 = w2[pid][0]
		eF = poly.multiply_linear(servers, eF)

		for p in servers:
			pid = p.id
			p.temp1 = w3[pid][0]
		eF = poly.multiply_linear(servers, eF)

		for p in servers:
			pid = p.id
			p.temp1 = w4[pid][0]
		eF = poly.multiply_linear(servers, eF)

		for p in servers:
			pid = p.id
			p.temp1 = w1[pid][0]
	
		quorum = mset.quorum(servers, eF, 3)
		self.assertTrue(quorum)

	def test_quorum_not(self):
		eF = mset.initialize()
		
		s1 = group.random(ZR)
		s2 = group.random(ZR)
		s3 = group.random(ZR)
		s4 = group.random(ZR)

		w1, v, e0, rr = sec_share.share_encode(s1)
		w2, v, e0, rr = sec_share.share_encode(s2)
		w3, v, e0, rr = sec_share.share_encode(s3)
		w4, v, e0, rr = sec_share.share_encode(s4)
		for j in range(3): # agregamos s1 3 veces
			for p in servers:
				pid = p.id
				p.temp1 = w1[pid][0]
			eF = poly.multiply_linear(servers, eF)
		
		for p in servers:
			pid = p.id
			p.temp1 = w2[pid][0]
		eF = poly.multiply_linear(servers, eF)

		for p in servers:
			pid = p.id
			p.temp1 = w2[pid][0]
		eF = poly.multiply_linear(servers, eF)

		for p in servers:
			pid = p.id
			p.temp1 = w4[pid][0]
		eF = poly.multiply_linear(servers, eF)

		for p in servers:
			pid = p.id
			p.temp1 = w2[pid][0]
	
		quorum = mset.quorum(servers, eF, 3)
		self.assertFalse(quorum)

	def test_who_too(self):
		valid_accusers = []
		for i in range(10):
			user = User(i, n)
			valid_accusers += [user]

		mac_k = 3
		q = 2

		wt = WhoToo(k, n, q, mac_k, valid_accusers)
		wt.accuse(valid_accusers[0], 'persona1')
		wt.accuse(valid_accusers[2], 'persona2')
		res = wt.accuse(valid_accusers[1], 'persona1')
		self.assertIsNotNone(res)

	def test_who_too_noquorum(self):
		valid_accusers = []
		for i in range(10):
			user = User(i, n)
			valid_accusers += [user]

		mac_k = 3
		q = 2

		wt = WhoToo(k, n, q, mac_k, valid_accusers)
		wt.accuse(valid_accusers[0], 'persona1')
		res = wt.accuse(valid_accusers[1], 'persona3')
		self.assertIsNone(res)


	




		




if __name__ == '__main__':
	unittest.main()
