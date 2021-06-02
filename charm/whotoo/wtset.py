from privatepoly import PrivatePoly
from charm.toolbox.pairinggroup import ZR

class PrivateMultiset():

	def __init__(self, sec_share, eg, pkeg):
		self.poly = PrivatePoly(sec_share, eg, pkeg)
		self.sec_share = sec_share
		self.eg = eg
		self.pkeg = pkeg

	def initialize(self):
		return [self.eg.enc(self.pkeg, self.pkeg['g'])]

	# shares of s in temp1
	def add(self, servers, eF):
		return self.poly.multiply_linear(servers, eF)

	# shares of s in temp1
	def quorum(self, servers, eF, q):
		r = []
		for i in range(q):
			ri = self.sec_share.group.random(ZR)
			r += [ri]

		eG = self.poly.multiply(eF, r)
		eH = self.poly.differentiate(eG, q-1)
		return self.poly.zero_test(servers, eH)
