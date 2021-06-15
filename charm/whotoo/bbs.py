import charm.toolbox.symcrypto
from util import pedersen_commit, zklogeq, zklogeq_verify
from charm.toolbox.hash_module import *
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,order
from charm.core.engine.util import objectToBytes,bytesToObject
from charm.toolbox.secretshare import *
from hashlib import sha256

class BBS():

	def __init__(self, group, g1, g2, h, w, sec_share):
		self.group = group
		self.sec_share = sec_share
		self.u = g1
		self.v = h
		self.g1 = g1
		self.g2 = g2
		self.w = w
		self.h = Hash(pairingElement=self.group)

	def key_issue(self, servers, user):
		self.sec_share.servers = servers
		r = self.sec_share.gen_inv()

		for p in self.sec_share.servers:
			pid = p.id
			alphai = p.temp4 - p.skbbs_share
			user.da_shares[pid-1] = alphai

		alpha_shares = {self.group.init(ZR, i): user.da_shares[i-1] for i in range(1, len(user.da_shares)+1)}
		alpha = self.sec_share.reconstruct(alpha_shares)

		user.alpha = alpha
		user.R = r

		return servers, r



	def phi(self, t1, t2, t3, c1, c2):
		tt1 = self.u ** t1
		tt2 = (c1 ** t2) * (self.u ** (-1 * t3))
		tt3 = (self.group.pair_prod(c2, self.g2) ** t2) * (self.group.pair_prod(self.v, self.w) ** (-1 * t1)) * (self.group.pair_prod(self.v, self.g2) ** (-1 * t3))
		return (tt1, tt2, tt3)

	def sign(self, sku, m):
		(r, alpha) = sku
		a = self.group.random(ZR)
		cR = ( self.u ** a, ( self.v ** a ) * r )
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
		t2 = self.group.init(ZR, 1)
		e1 = self.group.pair_prod(self.g1, self.g2)
		e2 = self.group.pair_prod(c2, self.w)
		t3 = (e1 * (e2 ** -1)) ** z

		rp = (calc[0] * (t1 ** -1), calc[1]* (t2 ** -1), calc[2] * (t3 ** -1))

		m_bytes = objectToBytes(m, self.group)
		cR_bytes = objectToBytes(cR, self.group)
		rp_bytes = objectToBytes(rp, self.group)

		hcalc = self.h.hashToZr(m_bytes, cR_bytes, rp_bytes)

		return z == hcalc
