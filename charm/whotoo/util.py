from charm.toolbox.pairinggroup import PairingGroup,ZR
from charm.core.engine.util import objectToBytes,bytesToObject
from charm.toolbox.hash_module import *

def pedersen_commit(g, h, msg, r):
	return (g ** msg) * (h ** r)

def zklogeq(group, g, h, x):
	r = group.random(ZR)
	a1 = g ** r
	a2 = h ** r
	a = (a1, a2)
	gx = g ** x

	a1_bytes = objectToBytes(a1, group)
	a2_bytes = objectToBytes(a2, group)
	g_bytes = objectToBytes(g, group)
	gx_bytes = objectToBytes(gx, group)


	h = Hash(pairingElement=group)
	c = h.hashToZr(g_bytes, gx_bytes, a1_bytes, a2_bytes)

	t = r + c*x

	return a, c, t

def zklogeq_verify(g, h, gx, hx, a, c, t):
	a1, a2 = a
	v1 = (g ** t == a1 * (gx ** c))
	v2 = (h ** t == a2 * (hx ** c))
	return (v1 and v2)


def mr_prove(group, c1, c2, a1, a2, r):
		k = group.random(ZR)
		b1 = c1 ** k
		b2 = c2 ** k
		a1b = objectToBytes(a1, group)
		a2b = objectToBytes(a2, group)
		b1b = objectToBytes(b1, group)
		b2b = objectToBytes(b2, group)
		c1b = objectToBytes(c1, group)
		c2b = objectToBytes(c2, group)

		hashfunc = Hash(pairingElement=group)
		alpha = hashfunc.hashToZr(a1b, a2b, b1b, b2b, c1b, c2b)
		beta = alpha * k + r
		return (beta, b1, b2)

def mr_verify(group, c1, c2, pi, a1, a2):
	beta, b1, b2 = pi
	a1b = objectToBytes(a1, group)
	a2b = objectToBytes(a2, group)
	b1b = objectToBytes(b1, group)
	b2b = objectToBytes(b2, group)
	c1b = objectToBytes(c1, group)
	c2b = objectToBytes(c2, group)
	hashfunc = Hash(pairingElement=group)
	alpha = hashfunc.hashToZr(a1b, a2b, b1b, b2b, c1b, c2b)
	return (c1 ** beta == a1 * (b1 ** alpha)) and (c2 ** beta == a2 * (b2 ** alpha))




class Accusation():
	id = None
	cR = None
	cD = None
	wi = None
	wiq = None
	v = None
	vq = None
	e0 = None
	e0q = None
	sigma = None
	pi0 = None
	pi1 = None

	def __init__(self, id, cR, cD, wi, wiq, v, vq, e0, e0q, sigma, pi0, pi1):
		self.id = id
		self.cR = cR
		self.cD = cD
		self.wi = wi
		self.wiq = wiq
		self.v = v
		self.vq = vq
		self.e0 = e0
		self.e0q = e0q
		self.sigma = sigma
		self.pi0 = pi0
		self.pi1 = pi1


class User():

	def __init__(self, id, n):
		self.id = id
		self.da_shares = [0] * n
		self.R = None
		self.tau = None
		self.alpha = None
		self.macs = []
		self.temp = None
		self.next_mac = 0

class Server():
	

	# accusations = {}
	# unique_accs = set()
	# accs = {}
	# reused_vals = set()
	

	def __init__(self, id, n):
		self.id = id
		self.da_shares = [0] * n
		self.skeg_share = None
		self.skbbs_share = None
		self.skdiprf_share = None
		self.skibe_share = None
		self.last_acc = None
		self.temp1 = None
		self.temp2 = None
		self.temp3 = None
		self.temp4 = None
		self.temp5 = None
		self.temp6 = None
		self.temp7 = None
		self.beaver = None
		self.gen = []
