from typing import get_type_hints
import charm.toolbox.symcrypto
from util import pedersen_commit, zklogeq, zklogeq_verify
from charm.toolbox.hash_module import *
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,order
from charm.core.engine.util import objectToBytes,bytesToObject
from charm.toolbox.secretshare import *
from hashlib import sha256

class DistIBE():

	def __init__(self, group, g1, g2, g1p, sec_share):
		self.group = group
		self.g1 = g1
		self.g2 = g2
		self.g1p = g1p
		self.gp = group.random(GT)
		self.hp = group.random(GT)
		self.h = group.random(G2)
		self.H = Hash(pairingElement=self.group)
		self.sec_share = sec_share

	# shares of msk in skibe_share
	def key_gen(self, servers, id):
		# gamma_shares = {}
		# for p in servers:
		# 	dk = self.group.init(ZR, p.id)
		# 	gamma_shares[dk] = p.skibe_share
		# msk = self.sec_share.reconstruct(gamma_shares)

		w, v, e0, rr = self.sec_share.share_encode(id)
		for p in servers:
			pid = p.id
			p.temp1 = p.skibe_share - w[pid][0] # gamma en temp1

		servers = self.sec_share.invert(servers) #gamma^-1 en temp3
		for p in servers:
			p.temp1 = p.temp3 # gamma^-1 en temp1

		rid = self.group.random(ZR)
		base = (self.h * (self.g2 ** (-1 * rid)))
		hid = self.sec_share.exp(servers, base)

		# hide= (self.h * (self.g2 ** (-1 * rid))) ** ((msk-id) ** -1)
		# print(hid == hide)

		return (id, rid, hid)

	# shares of id en temp1
	def enc(self, servers):

		# gamma_shares = {}
		# for p in servers:
		# 	dk = self.group.init(ZR, p.id)
		# 	gamma_shares[dk] = p.temp1
		# id = self.sec_share.reconstruct(gamma_shares)

		servers = self.sec_share.gen(servers) # shares de dec en temp2

		# gamma_shares = {}
		# for p in servers:
		# 	dk = self.group.init(ZR, p.id)
		# 	gamma_shares[dk] = p.temp2
		# dec = self.sec_share.reconstruct(gamma_shares)

		for p in servers:
			p.temp4 = p.temp1 # id en temp4
			p.temp5 = p.temp2 # dec en temp5
			p.temp6 = p.temp1 # id en temp6

		com = self.sec_share.multexp(servers, self.gp, self.hp)

		servers = self.sec_share.gen(servers) # shares de s en temp2

		# gamma_shares = {}
		# for p in servers:
		# 	dk = self.group.init(ZR, p.id)
		# 	gamma_shares[dk] = p.temp2
		# s = self.sec_share.reconstruct(gamma_shares)

		for p in servers:
			p.temp4 = p.temp5 # dec en temp4
			p.temp5 = p.temp2 # s en temp5
			p.temp1 = p.temp2 # s en temp1
			p.temp7 = p.temp2 # s en temp7


		epair = self.group.pair_prod(self.g1, self.g2)
		c2 = self.sec_share.exp(servers, epair)

		epair2 = self.group.pair_prod(self.g1, self.h) ** -1
		c3 = self.sec_share.multexp(servers, self.hp, epair2)

		for p in servers:
			p.temp1 = p.temp6 # id en temp1

		servers = self.sec_share.gen(servers) # shares de t en temp2

		# gamma_shares = {}
		# for p in servers:
		# 	dk = self.group.init(ZR, p.id)
		# 	gamma_shares[dk] = p.temp2
		# t = self.sec_share.reconstruct(gamma_shares)

		servers = self.sec_share.mult(servers) # id*t en temp3

		for p in servers:
			p.temp1 = p.temp2 # t en temp1
			p.temp4 = p.temp2 # t en temp4
			p.temp5 = p.temp3 # id*t en temp5

		servers = self.sec_share.invert(servers) # t^-1 en temp3
		for p in servers:
			p.temp6 = p.temp3 # t^-1 en temp6

		g11 = self.g1 ** -1
		a = self.sec_share.multexp(servers, self.g1p, g11)

		for p in servers:
			p.temp1 = p.temp7 # s en temp1
			p.temp2 = p.temp6 #t^-1 en temp2

		servers = self.sec_share.mult(servers) # s*t^-1 en temp3
		for p in servers:
			p.temp1 = p.temp3 # s*t^-1 en temp1

		c1 = self.sec_share.exp(servers, a)

		# come = (self.gp ** id) * (self.hp ** dec)
		# c1e = (self.g1p ** s) * (self.g1 ** (-1 * s * id))
		# c2e = self.group.pair_prod(self.g1, self.g2) ** s
		# c3e = (self.hp ** dec) * (self.group.pair_prod(self.g1, self.h) ** (-1 * s))

		# print(come == com)
		# print(c1e == c1)
		# print(c2e == c2)
		# print(c3e == c3)
		return (com, c1, c2, c3)


	def dec(self, skid, c):
		id, rid, hid = skid
		com, c1, c2, c3 = c
		epair = self.group.pair_prod(c1, hid)
		hdec = epair * (c2 ** rid) * c3
		gdec = self.gp ** id
		expected = gdec * hdec
		ver = (com == expected)
		return ver

		
