from hashlib import sha256
import charm.toolbox.symcrypto
from charm.toolbox.hash_module import *
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1
from charm.core.engine.util import objectToBytes,bytesToObject
from charm.toolbox.secretshare import *

class ElGamal():

	def __init__(self, group=None):
		if group:
			self.group = group
		else:
			self.group = PairingGroup('BN254')
			

	def gen_keys(self):
		g = self.group.random(G1)
		x = self.group.random(ZR)
		h = g ** x
		skeg = x
		pkeg = {'g': g, 'h': h}
		return (pkeg, skeg)


	def enc(self, pk, msg, a=None):
		if not a:
			a = self.group.random(ZR)
		c1 = pk['g'] ** a
		s = pk['h'] ** a
		c2 =  s * msg
		return (c1, c2)

	def dec(self, sk, c):
		c1, c2 = c
		s = c1 ** sk
		m = c2 * (s ** -1)
		return m

	def enc_string(self, pk, msg, a=None):
		if not a:
			a = self.group.random(ZR)
		ha = pk['h'] ** a
		ha_bytes = objectToBytes(ha, self.group)
		key = sha256(ha_bytes).digest()
		authsym = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(key)
		c1 = pk['g'] ** a
		m = msg.encode()
		c2 = authsym.encrypt(m)
		return (c1, c2)

	def dec_string(self, sk, c):
		(c1, c2) = c
		c1x = c1 ** sk
		c1x_bytes = objectToBytes(c1x, self.group)
		key = sha256(c1x_bytes).digest()
		authsym = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(key)
		m = authsym.decrypt(c2)
		msg = m.decode()
		return msg

	def prove(self, pk, c, a, rho):
		r = self.group.random(ZR)
		t = pk['g'] ** r
		t_bytes = objectToBytes(t, self.group)
		c1, c2 = c
		c1_bytes = objectToBytes(c1, self.group)
		c2_bytes = objectToBytes(c2, self.group)
		rho_bytes = objectToBytes(rho, self.group) #revisar segun q va a ser rho dps
		h = Hash(pairingElement=self.group)
		z = h.hashToZr(c1_bytes, c2_bytes, t_bytes, rho_bytes)
		s = r + z*a
		return (t,s)

	def verify(self, pk, pi, c, rho):
		t, s = pi
		t_bytes = objectToBytes(t, self.group)
		c1, c2 = c
		c1_bytes = objectToBytes(c1, self.group)
		c2_bytes = objectToBytes(c2, self.group)
		rho_bytes = objectToBytes(rho, self.group) #revisar segun q va a ser rho dps
		h = Hash(pairingElement=self.group)
		z = h.hashToZr(c1_bytes, c2_bytes, t_bytes, rho_bytes)
		gs = pk['g'] ** s
		return gs == t*(c1 ** z) 




