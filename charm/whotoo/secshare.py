import charm.toolbox.symcrypto
from tqdm.contrib.concurrent import thread_map
from util import pedersen_commit, zklogeq, zklogeq_verify, mr_prove, mr_verify
from charm.toolbox.hash_module import *
from charm.toolbox.pairinggroup import PairingGroup,ZR
from charm.core.engine.util import objectToBytes
from charm.toolbox.secretshare import *
from hashlib import sha256

class SecShare():

	def __init__(self, group, g, g2, k, n, el, servers=None):
		self.k = k
		self.n = n
		self.group = group
		self.ss = SecretShare(self.group, verbose_status=False)
		self.g = g
		self.g2 = g2
		self.el = el
		shares = {self.group.init(ZR, i):0 for i in range(1, self.n + 1)}
		self.coeffs = self.ss.recoverCoefficients(shares)
		self.broadcast = {}
		self.h = None
		self.next_gen = 0
		self.servers = servers
		# self._lock = threading.Lock()


	def gen_pedersen(self, s, r, feldman=False):
		s_shares, s_coeffs = self.ss.genShares(s, k=self.k, n=self.n)
		r_shares, r_coeffs = self.ss.genShares(r, k=self.k, n=self.n)

		w = list(zip(s_shares, r_shares))
		v = []

		if feldman:
			v_feldman =[]

		for i in range(len(s_coeffs)):
			vi = pedersen_commit(self.g, self.h, s_coeffs[i], r_coeffs[i])
			v += [vi]

			if feldman:
				vif = self.g ** s_coeffs[i]
				v_feldman += [vif]

		if feldman:
			return w, v, v_feldman

		return w, v


	def verify_pedersen(self, si, ri, v, i):
		expected = (self.g ** si) * (self.h ** ri)
		verification = v[0]
		for j in range(1, len(v)):
			verification *= ( v[j] ** (i ** j) )

		return expected == verification


	def verify_feldman(self, si, v, i):
		expected = self.g ** si
		verification = v[0]

		for j in range(1, len(v)):
			verification *= v[j] ** (i ** j)

		return expected == verification


	def reconstruct(self, shares):
		return self.ss.recoverSecret(shares)


	def share_encode(self, s):
		r = self.group.random(ZR)
		w, v = self.gen_pedersen(s, r)
		e0 = self.g ** r

		return w, v, e0, r

	# s, r = w, shares de r tienen que estar en temp1
	def check_consistent(self, e0):
		return e0 == self.exp(self.g)


	# b ^ shares temp 1 de servers
	def exp(self, b):
		def temp_func1(p):
			bs = b ** p.temp1
			gs = self.g ** p.temp1
			proof = zklogeq(self.group, self.g, b, p.temp1)
			var_name = 'exp_vals_' + str(p.id)
			self.broadcast[var_name] = (bs, gs, proof)

		# for p in servers:
		# 	temp_func1(p)
		# p_umap(temp_func1, servers)
		thread_map(temp_func1, self.servers, leave=False)

		def temp_func2(p):
			for s in self.servers:
				if p.id != s.id:
					var_name = 'exp_vals_' + str(s.id)
					bs, gs, proof = self.broadcast[var_name]
					a, c, t = proof
					ver = zklogeq_verify(self.g, b, gs, bs, a, c, t)
					if not ver:
						raise Exception('Failed to verify log equality from ' + str(p.id) + ' to ' + str(s.id))

		# for p in servers:
		# 	temp_func2(p)
		# p_umap(temp_func2, servers)
		thread_map(temp_func2, self.servers, leave=False)

		res = 1
		for p in self.servers:
			pid = self.group.init(ZR, p.id)
			var_name = 'exp_vals_' + str(p.id)
			bs, gs, proof = self.broadcast[var_name]
			res *= (bs ** self.coeffs[pid])

		return res

	
	# temp1 * temp2 = temp3
	def mult2(self, servers):
		for p in servers:
			pid = p.id
			z = p.temp1 * p.temp2
			w, v, e0, r = self.share_encode(z)

			for s in servers:
				sid = s.id
				s.da_shares[pid-1] = w[sid][0]
		
		for p in servers:
			new_share = 0
			for s in servers:
				sidg = self.group.init(ZR, s.id)
				sid = s.id
				new_share += self.coeffs[sidg] * p.da_shares[sid-1]
			p.temp3 = new_share

		return servers

	# temp1 * temp2 = temp3 # beaver
	def mult(self):
		def temp_func1(p):
			a, b, c = p.beaver
			x = p.temp1
			y = p.temp2
			d = x - a
			e = y - b
			var_name = 'mult_' + str(p.id)
			# with self._lock:
			self.broadcast[var_name] = (d, e)

		# with concurrent.futures.ThreadPoolExecutor(max_workers=self.n) as executor:
		# 	executor.map(temp_func1, servers)
		thread_map(temp_func1, self.servers, leave=False)

		d_shares = {}
		e_shares = {}
		for p in self.servers:
			var_name = 'mult_' + str(p.id)
			d, e = self.broadcast[var_name]

			dk = self.group.init(ZR, p.id)
			d_shares[dk] = d
			e_shares[dk] = e

		d_rec = self.reconstruct(d_shares)
		e_rec = self.reconstruct(e_shares)

		def temp_func2(p):
			pid = p.id
			a, b, c = p.beaver
			x = p.temp1
			y = p.temp2
			z = c + x * e_rec + y * d_rec - e_rec * d_rec
			p.temp3 = z

		# with concurrent.futures.ThreadPoolExecutor(max_workers=self.n) as executor:
		# 	executor.map(temp_func2, servers)
		thread_map(temp_func2, self.servers, leave=False)



	# shares de s en temp1
	def expRR(self, e):
		e0, e1 = e

		def temp_func(p):
			r = self.group.random(ZR)
			gr = self.g ** r
			hr = self.h ** r
			ep0 = gr * (e0 ** p.temp1)
			ep1 = hr * (e1 ** p.temp1)

			# agregar proof of knowledge of r
			# c = (gr, ep1)
			# pkeg = {'g': self.g, 'h': self.h}
			# pi1 = self.el.prove(pkeg, c, r, 0)

			# equality of discrete log
			# pi2 = zklogeq(self.group, self.g, self.h, r)

			var_name = 'expRR_' + str(p.id)
			# with self._lock:
			self.broadcast[var_name] = (ep0, ep1) #pi1, pi2

		# with concurrent.futures.ThreadPoolExecutor(max_workers=self.n) as executor:
		# 	executor.map(temp_func, servers)
		thread_map(temp_func, self.servers, leave=False)

		# verify proofs
		# for p in servers:
		# 	for s in servers:
		# 		if p.id != s.id:
		# 			var_name = 'expRR_' + str(s.id)
		# 			es0, es1, pi = self.broadcast[var_name]

		res0 = 1
		res1 = 1
		for p in self.servers:
			pid = self.group.init(ZR, p.id)
			var_name = 'expRR_' + str(p.id)
			ep0, ep1 = self.broadcast[var_name]
			res0 *= (ep0 ** self.coeffs[pid])
			res1 *= (ep1 ** self.coeffs[pid])

		return (res0, res1)


	# shares quedan en temp2
	def gen(self, prev=True):

		if (self.next_gen < len(self.servers[1].gen)-1) and prev:
			def temp_func(p):
				p.temp2 = p.gen[self.next_gen]
				
			self.next_gen += 1
			thread_map(temp_func, self.servers, leave=False)

		else:	
			

			def temp_func1(p):
				pid = p.id
				z = self.group.random(ZR)
				r = self.group.random(ZR)
				w, v = self.gen_pedersen(z, r)

				for s in self.servers:
					sid = s.id
					s.da_shares[pid-1] = w[sid]

				var_name = 'gen_pedersen_' + str(pid)
				# with self._lock:
				self.broadcast[var_name] = v

			thread_map(temp_func1, self.servers, leave=False)

			def temp_func2(p):
				pid = p.id
				p.temp2 = 0
				# p.temp2 = (0, 0)

				for s in self.servers:
					sid = s.id
					si, ri = p.da_shares[sid-1]

					if pid != sid:
						var_name = 'gen_pedersen_' + str(sid)
						vp = self.broadcast[var_name]
						verp = self.verify_pedersen(si, ri, vp, pid)

						if not verp:
							raise Exception('Server ' + str(pid) + ' failed to verify share from server ' + str(sid) + ' when generating random value')

					# new_x, new_r = p.temp2
					new_x = p.temp2
					new_x += si
					p.temp2 = new_x
					#new_r += ri
					# p.temp2 = (new_x, new_r)

			thread_map(temp_func2, self.servers, leave=False)



	# shares quedan en temp2
	def geng(self):
		def temp_func1(p):
			pid = p.id
			z = self.group.random(ZR)
			r = self.group.random(ZR)
			w, v, vf = self.gen_pedersen(z, r, feldman=True)

			for s in self.servers:
				sid = s.id
				s.da_shares[pid-1] = w[sid]

			var_name1 = 'gen_feldman_' + str(pid)
			var_name2 = 'gen_pedersen_' + str(pid)
			# with self._lock:
			self.broadcast[var_name1] = vf
			self.broadcast[var_name2] = v

		thread_map(temp_func1, self.servers, leave=False)

		def temp_func2(p):
			pid = p.id
			#p.temp2 = (0, 0)
			p.temp2 = 0

			for s in self.servers:
				sid = s.id
				si, ri = p.da_shares[sid-1]

				if pid != sid:
					var_name = 'gen_feldman_' + str(sid)
					vf = self.broadcast[var_name]
					var_name = 'gen_pedersen_' + str(sid)
					vp = self.broadcast[var_name]

					verf = self.verify_feldman(si, vf, pid)
					verp = self.verify_pedersen(si, ri, vp, pid)

					if not (verf and verp):
						raise Exception('Server ' + str(pid) + ' failed to verify share from server ' + str(sid) + ' when generating random value')

				# new_x, new_r = p.temp2
				new_x = p.temp2
				new_x += si
				p.temp2 = new_x
				#new_r += ri
				# p.temp2 = (new_x, new_r)
		
		thread_map(temp_func2, self.servers, leave=False)

		h = 1
		for p in self.servers:
			var_name = 'gen_feldman_' + str(p.id)
			vf = self.broadcast[var_name]
			h *= vf[0]

		return h

	# en temp1 estan shares, resultado en temp 3
	def invert(self):
		self.gen()
		self.mult()

		w_shares = {}
		for p in self.servers:
			dk = self.group.init(ZR, p.id)
			w_shares[dk] = p.temp3

		w = self.reconstruct(w_shares)
		winv = w ** -1

		def temp_func(p):
			p.temp3 = p.temp2 * winv

		thread_map(temp_func, self.servers, leave=False)
		

	# res in temp2
	def gen_zero(self):
		z = self.group.init(ZR, 0)
		r = self.group.random(ZR)

		def temp_func1(p):
			pid = p.id
			w, v, vf = self.gen_pedersen(z, r, feldman=True)

			var_name = 'gen_zero_feldman_' + str(pid)
			# with self._lock:
			self.broadcast[var_name] = vf

			for s in self.servers:
				sid = s.id
				s.da_shares[pid-1] = w[sid][0]

		thread_map(temp_func1, self.servers, leave=False)


		def temp_func2(p):
			pid = p.id
			p.temp2 = 0

			for s in self.servers:
				sid = s.id
				si = p.da_shares[sid-1]

				if sid != pid:
					var_name = 'gen_zero_feldman_' + str(sid)
					vf = self.broadcast[var_name]

					ver = self.verify_feldman(si, vf, pid)

					if not ver:
						raise Exception('Server ' + str(pid) + ' failed to verify zero sharing of server ' + str(sid))

				p.temp2 += si

		thread_map(temp_func2, self.servers, leave=False)



	# shares resultantes en temp4
	def gen_inv(self): 
		self.gen() # x en temp2

		def temp_func1(p):
			p.temp1 = p.temp2 # x en temp1
			p.temp4 = p.temp2 # a en temp4

		thread_map(temp_func1, self.servers, leave=False)

		self.invert() # x^-1 en temp3

		def temp_func2(p):
			p.temp1 = p.temp3 # x^-1 en temp1

		thread_map(temp_func2, self.servers, leave=False)

		gx = self.exp(self.g)
		return gx


	# clave en skeg_share
	def dist_dec(self, c):
		c1, c2 = c

		def temp_func(p):
			p.temp1 = p.skeg_share

		thread_map(temp_func, self.servers, leave=False)

		d = self.exp(c1)
		return c2/d


	# clave en skeg_share
	def dist_dec_str(self, c):
		c1, c2 = c

		def temp_func(p):
			p.temp1 = p.skeg_share

		thread_map(temp_func, self.servers, leave=False)

		d = self.exp(c1)
		d_bytes = objectToBytes(d, self.group)
		key = sha256(d_bytes).digest()
		authsym = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(key)
		
		return authsym.decrypt(c2)

	# shares en temp4 y temp5
	def multexp(self, b1, b2):
		self.gen() # shares de t en temp2
		def temp_func1(p):
			p.temp1 = p.temp4 # alpha en temp1

		thread_map(temp_func1, self.servers, leave=False)

		self.mult() #  alpha*t en temp3
		def temp_func2(p):
			p.temp1 = p.temp3 # alpha*t en temp1

		thread_map(temp_func2, self.servers, leave=False)

		b1alpha = self.exp(b1)
		def temp_func3(p):
			p.temp1 = p.temp5 # beta en temp1

		thread_map(temp_func3, self.servers, leave=False)

		self.mult() #  beta*t en temp3
		thread_map(temp_func2, self.servers, leave=False) # beta*t en temp1
			
		b2beta = self.exp(b2)

		base = b1alpha * b2beta
		def temp_func4(p):
			p.temp1 = p.temp2 # t en temp1

		thread_map(temp_func4, self.servers, leave=False)

		self.invert() #t^-1 en temp3
		thread_map(temp_func2, self.servers, leave=False) # t^-1 en temp1
		# for p in servers:
		# 	p.temp1 = p.temp3 
		
		res = self.exp(base)

		return res

	# recipinets = None implica all das, output en temp2
	# x input en temp1
	def diprf(self, recipient=None):
		self.gen() # shares de r en temp2
		def temp_func1(p):
			p.temp1 = p.skdiprf_share + p.temp1 # t1=sk+x en temp1

		thread_map(temp_func1, self.servers, leave=False)

		self.invert() # t1^-1 en temp3
		def temp_func2(p):
			p.temp1 = p.temp3 # t1=sk+x en temp3

		thread_map(temp_func2, self.servers, leave=False)

		epair = self.group.pair_prod(self.g, self.g2)

		if recipient is None:
			res = self.exp(epair)
			return res

		def temp_func3(p):
			pid = p.id
			recipient.da_shares[pid-1] = epair ** p.temp1
		
		thread_map(temp_func3, self.servers, leave=False)

		return recipient

	
	def msg_rand(self, c):
		c1, c2 = c
		def temp_func1(p):
			r = self.group.random(ZR)
			a1 = c1 ** r
			a2 = c2 ** r
			pi = mr_prove(self.group, c1, c2, a1, a2, r)
			var_name = 'msgrand_'+ str(p.id)
			# with self._lock:
			self.broadcast[var_name] = (pi, a1, a2)

		thread_map(temp_func1, self.servers, leave=False)

		def temp_func2(p):
			for s in self.servers:
				sid = s.id
				if p.id != sid:
					var_name = 'msgrand_'+ str(sid)
					pi, a1, a2 = self.broadcast[var_name]
					ver = mr_verify(self.group, c1, c2, pi, a1, a2)
					if not ver:
						raise Exception('Failed to verify during MsgRand')

		thread_map(temp_func2, self.servers, leave=False)
		
		c1p = 1
		c2p = 1
		for p in self.servers:
			var_name = 'msgrand_'+ str(p.id)
			pi, a1, a2 = self.broadcast[var_name]
			c1p *= a1
			c2p *= a2

		cp = (c1p, c2p)
		mp = self.dist_dec(cp)

		return mp
		
	





		










		















