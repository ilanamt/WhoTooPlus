# from hashlib import sha256
# import charm.toolbox.symcrypto
# from charm.toolbox.hash_module import *
# from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,order
# #pair_prod
# from charm.core.engine.util import objectToBytes,bytesToObject
# from charm.toolbox.secretshare import *
# import threading

# # cambios en charm> 
# # generate sharing tb devuelve coefficientes
# # reconstruct sharings se cambia el 0 pq tiene q ser pairing element

# class WhoToo():

# 	group = None
# 	g = None
# 	h = None

# 	el_gamal = None
# 	sec_share = None
# 	dist_bbs = None
# 	set_operations = None

# 	def __init__(self, k, n):
# 		self.group = PairingGroup('BN254')
# 		self.el_gamal = ElGamal(self.group)
# 		(pkeg, skeg) = self.el_gamal.gen_keys()
# 		self.g = pkeg['g']
# 		self.h = pkeg['h']
# 		self.sec_share = SecShare(self.group, self.g, self.h, k, n, self.el_gamal)

# class ElGamal():
# 	group = None
# 	pkeg = None
# 	skeg = None

# 	def __init__(self, group):
# 		self.group = group
			

# 	def gen_keys(self):
# 		g = self.group.random(G1)
# 		x = self.group.random(ZR)
# 		h = g ** x
# 		self.skeg = {'x': x}
# 		self.pkeg = {'g': g, 'h': h}
# 		return (self.pkeg, self.skeg)


# 	def enc(self, a, msg):
# 		c1 = self.pkeg['g'] ** a
# 		s = self.pkeg['h'] ** a
# 		c2 = msg * s
# 		return {'c1': c1, 'c2': c2}

# 	def dec(self, c):
# 		s = c['c1'] ** self.skeg['x']
# 		m = c['c2'] * (s ** -1)
# 		return m

# 	def enc_string(self, a, m):
# 		#a = self.group.random()
# 		ha = pkeg['h'] ** a
# 		ha_bytes = objectToBytes(ha, self.group)
# 		key = sha256(ha_bytes).digest()
# 		authsym = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(key)
# 		c1 = self.pkeg['g'] ** a
# 		M = m.encode()
# 		c2 = authsym.encrypt(M)
# 		return (c1, c2)

# 	def dec_string(self, c):
# 		(c1, c2) = c
# 		c1x = c1 ** self.skeg['x']
# 		c1x_bytes = objectToBytes(c1x, self.group)
# 		key = sha256(c1x_bytes).digest()
# 		authsym = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(key)
# 		m = authsym.decrypt(c2)
# 		M = m.decode()
# 		return M

# 	def prove(self, c, a, rho):
# 		r = group.random(ZR)
# 		t = self.pkeg['g'] ** r
# 		t_bytes = objectToBytes(t, self.group)
# 		c1 = c['c1']
# 		c2 = c['c2']
# 		c1_bytes = objectToBytes(c1, self.group)
# 		c2_bytes = objectToBytes(c2, self.group)
# 		rho_bytes = objectToBytes(rho, self.group) #revisar segun q va a ser rho dps
# 		h = Hash(pairingElement=self.group)
# 		z = h.hashToZr(c1_bytes, c2_bytes, t_bytes, rho_bytes)
# 		s = r + z*a
# 		return (t,s)

# 	def verify(self, pi, c, rho):
# 		t, s = pi
# 		t_bytes = objectToBytes(t, self.group)
# 		c1 = c['c1']
# 		c2 = c['c2']
# 		c1_bytes = objectToBytes(c1, self.group)
# 		c2_bytes = objectToBytes(c2, self.group)
# 		rho_bytes = objectToBytes(rho, self.group) #revisar segun q va a ser rho dps
# 		h = Hash(pairingElement=self.group)
# 		z = h.hashToZr(c1_bytes, c2_bytes, t_bytes, rho_bytes)
# 		gs = self.pkeg['g'] ** s
# 		return gs == t*(c1 ** z) 

# 	# revisar
# 	def dist_dec(self, c1, c2, x):
# 		di = SecShare.Exp(c1, x)
# 		d = SecShare.Reconstruc(di)
# 		return c2/d


# 	# revisar
# 	def dist_dec_str(self, c1, c2, x):
# 		di = SecShare.Exp(c1, x)
# 		d = SecShare.Reconstruc(di)
# 		key = sha256(d).digest()
# 		authsym = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(key)
# 		return authsym.decrypt(c2)




# def pedersen_commit(g, h, msg, r):
# 	return (g ** msg) * (h ** r)


# def zklogeq(group, g, h, x):
# 	r = group.random(ZR)
# 	a1 = g ** r
# 	a2 = h ** r
# 	a = (a1, a2)
# 	gx = g ** x

# 	a1_bytes = objectToBytes(a1, group)
# 	a2_bytes = objectToBytes(a2, group)
# 	g_bytes = objectToBytes(g, group)
# 	gx_bytes = objectToBytes(gx, group)


# 	h = Hash(pairingElement=group)
# 	c = h.hashToZr(g_bytes, gx_bytes, a1_bytes, a2_bytes)

# 	t = r + c*x

# 	return a, c, t

# def zklogeq_verify(g, h, gx, hx, a, c, t):
# 	a1, a2 = a
# 	v1 = (g ** t == a1 * (gx ** c))
# 	v2 = (h ** t == a2 * (hx ** c))
# 	return (v1 and v2)


# class SecShare():
# 	group = None
# 	ss = None
# 	k = 0
# 	n = 0
# 	g = None
# 	h = None
# 	el = None

# 	def __init__(self, group, g, h, k, n, el):
# 		self.k = k
# 		self.n = n
# 		self.group = group
# 		self.ss = SecretShare(self.group, verbose_status=False)
# 		self.g = g
# 		self.h = h
# 		self.el = el

# 	def gen_pedersen(self, s, r):
# 		s_shares, s_coeffs = self.ss.genShares(s, k=self.k, n=self.n)
# 		r_shares, r_coeffs = self.ss.genShares(r, k=self.k, n=self.n)

# 		w = list(zip(s_shares, r_shares))
# 		v = []

# 		v_feldman =[]

# 		for i in range(len(s_coeffs)):
# 			vi = pedersen_commit(self.g, self.h, s_coeffs[i], r_coeffs[i])
# 			vif = self.g ** s_coeffs[i]
# 			v += [vi]
# 			v_feldman += [vif]

# 		return w, v, v_feldman

# 	def gen_feldman(self, s):
# 		shares, coeffs = self.ss.genShares(s, k=self.k, n=self.n)
# 		v = [g ** coeff for coeff in coeffs]

# 		return shares, v

# 	def verify_feldman(self, si, v, i):
# 		expected = self.g ** si
# 		verification = v[0]

# 		for j in range(1, len(v)):
# 			verification *= v[j] ** (i ** j)

# 		return expected == verification


# 	def share_encode(self, s, feldman=False):
# 		r = self.group.random(ZR)
# 		w, v, v_feldman = self.gen_pedersen(s, r)
# 		e0 = self.g ** r

# 		if feldman:
# 			return w, v, e0, r, v_feldman

# 		return w, v, e0, r


# 	def verify(self, si, ri, v, i):
# 		expected = (self.g ** si) * (self.h ** ri)
# 		verification = v[0]
# 		for j in range(1, len(v)):
# 			verification *= ( v[j] ** (i ** j) )

# 		return expected == verification

# 	def check_consistent(self, w, v, e0):
# 		s_shares, r_shares = w
# 		return e0 == self.exp(self.g, r_shares)

# 	def expRR_prepare(self, e, si):
# 		e0, e1 = e
# 		ri = self.group.random(ZR)
# 		rho = self.group.random(ZR)

# 		c1g = self.g ** ri
# 		c2g = c1g * (e0 ** si)

# 		c1h = self.h ** ri
# 		c2g = c1h * (e1 ** si)

# 		cg = {'c1': c1g, 'c2': c2g}
# 		ch = {'c1': c1h, 'c2': c2h}

# 		pr = el.prove(cg, ri, rho)
# 		logeq = zklogeq(self.group, self.g, self.h, ri)

# 		return cg, ch, pr, logeq, rho

# 	def expRR_compute(self, cg, ch, pr, logeq, rho):
# 		a, c, t = logeq
# 		pr_verify = el.verify(pr, cg, rho)
# 		logeq_verify = zklogeq_verify(self.g, self.h, cg['c1'], ch['c1'], a, c, t)
# 		if not (pr_verify and logeq):
# 			raise Exception("Failed verifications for expRR")

# 		y1 = sum()


# 	def exp(self, b, s_share):
# 		bs = b ** s_share
# 		gs = self.g ** s_share
# 		proof = zklogeq(group, self.g, b, s_share)
# 		return (bs, gs, proof)

# 	def add(self, x1, x2):
# 		return x1 + x2

# 	def sub(self, x1, x2):
# 		return x1 - x2

# 	def mult_temp(self, s1, s2, N):
# 		s1_dict = {self.group.init(ZR, i): s1[i-1] for i in range(1, N+1)}
# 		s2_dict = {self.group.init(ZR, i): s2[i-1] for i in range(1, N+1)}

# 		s1_rec = self.reconstruct(s1_dict)
# 		s2_rec = self.reconstruct(s2_dict)

# 		s = s1_rec * s2_rec

# 		w, v, e0, r = self.share_encode(s)

# 		res = [a[0] for a in w]

# 		return res


# 	def mult2(self, m1, m2, servers, share_name, N):
# 		for p in servers:
# 			p_id = p.get('idx')

# 			print('p ', p_id)

# 			var_name1 = m1 + str(p_id)
# 			var_name2 = m2 + str(p_id)
# 			x1, r = p.get(var_name1)
# 			x2, r = p.get(var_name2)

# 			z = x1 * x2
# 			w, v, e0, r = sec_share.share_encode(z)

# 			for server in servers:
# 				s_id = server.get('idx')
# 				var_name = 'mult_share_' + str(p_id) + str(s_id)
# 				server.save(var_name, (w[s_id][0]))


# 		for p in servers:
# 			shares_dict = {}
# 			p_id = p.get('idx')

# 			for i in range(1, N+1):
# 				var_name = 'mult_share_' + str(i) + str(p_id)
# 				sh = p.get(var_name)
# 				shares_dict[GROUP.init(ZR, i)] = sh

# 			new_share = sec_share.reconstruct(shares_dict)
# 			var_name = 'm_share_' + str(p_id)
# 			p.save(var_name, new_share) 

# 		return servers



# 	def invert(self, shares):
# 		z_shares, gz = DKG()
# 		w_shares = self.mult(shares, z_shares)
# 		# armar dict
# 		w = self.reconstruct(w_shares)
# 		winv = w ** -1
# 		resulting_shares = [z_share * winv for z in z_shares]
# 		return resulting_shares


# 	def recoverCoefficients(self, list):
# 		coeff = {}
# 		for i in list:
# 			result = 1
# 			for j in list:
# 				if not (i == j):
# 					# lagrange basis poly
# 					result *= (0 - j) / (i - j)
# 			coeff[i] = result
# 		return coeff

# 	# shares is a dictionary
# 	def recoverCoefficientsDict(self, dict):
# 		coeff = {}
# 		for i in dict.values():
# 			result = 1
# 			for j in dict.values():
# 				if not (i == j):
# 					# lagrange basis poly
# 					result *= (0 - j) / (i - j)
# 			coeff[i] = result
# 		return coeff
		
# 	def reconstruct(self, shares):
# 		if len(shares) < self.k:
# 			raise Exception("Not enough shares")
# 		# shares_dict = {group.init(ZR, i): shares[i] for i in range(1, len(shares))}

# 		list_keys = shares.keys()
# 		coeff = self.recoverCoefficients(list_keys)

# 		secret = -1
# 		for i in list_keys:
# 			if secret == -1:
# 				secret = coeff[i] * shares[i]
# 			else:
# 				secret += (coeff[i] * shares[i])

# 		if secret == -1:
# 			return 0

# 		return secret


# 	def DKG(self, parties):
# 		z = []
# 		sharings = []

# 		for p in parties:
# 			zi = self.group.random(ZR)
# 			z += [zi]
# 			w, v, e0, r = share_encode(z)
# 			sharings += [(w, v)]
# 			# broadcast v
			
# 		final_shares = []
# 		for i in range(len(parties)):
# 			nsi = None
# 			nri = None

# 			for (w, v) in sharings:
# 				(si, ri) = w[i]
# 				verification = self.verify(si, ri, v, i)

# 				if not verification:
# 					raise Exception('Verification failed')
# 					# if complaint, broadcast share
# 						# diqualify parties that received more than t complains
# 						# or broadcasted shares that dont verify
# 				if nsi == None:
# 					nsi = si
# 					nri = ri
# 				else:
# 					nsi += si
# 					nri += ri

# 			# shares of shared secret x
# 			final_shares += [(nsi, nri)]

# 		# extracting g^x
# 		temp_shares = []
# 		for i in range(len(parties)):
# 			y = self.g ** z[i]
# 			y_shares, v = self.gen_pedersen
# 			temp_shares += [(y_shares, v)]

# 		for i in range(len(parties)):
# 			for (sh, v) in temp_shares:
# 				verification = self.verify_feldman(sh, v, i)
# 				if not verification:
# 					raise Exception('Verification failed')

# 		# revisar, cada party calcula multiplciando los yi q son los primeros valores de verificacion del sharing
# 		# por que cada uno no entrega no mas con proof de log? (ss. exp) y reconstruir


# 	def gen_zero(self, parties):
# 		for i in range(len(parties)):
# 			vals = []
# 			for j in range(len(parties)):
# 				z = self.group.random(ZR)
# 				values, coeffs = self.ss.genShares(z, k=self.k, n=self.n)
# 				vals += [(values, coeffs)]
# 			#enviar a los que corresponda sus shares

# 		#cada uno suma


	
# 	def gen_inv(self, shares, parties):
# 		a_shares, ga = self.DKG() 
# 		zero_shares = self.gen_zero()

# 		for i in range(1, len(a_shares)):
# 			val = shares[i] * a_shares[i] + zero_shares[i]
# 			# broadcast val
		
# 		reconstruct(val)
# 		for i in len(range(parties)):
# 			new_share = (val ** -1) * a_shares[i]


			

# class BBS():
# 	group = None
# 	g1 = None
# 	g2 = None
# 	u = None
# 	v = None
# 	w = None
# 	h = None

# 	def __init__(self, group, g1, h):
# 		self.group = group
# 		self.u = g
# 		self.v = h
# 		self.g1 = self.group.random(G1)
# 		self.g2 = self.group.random(G2)
# 		self.w = self.group.random(G2)
# 		self.h = Hash(pairingElement=self.group)

# 	def phi(self, t1, t2, t3, c1, c2):
# 		tt1 = self.u ** t1
# 		tt2 = (c1 ** t2) * (self.u ** (-1 * t3))
# 		tt3 = (self.group.pair_prod(c2, self.g2) ** t2) * (self.group.pair_prod(self.v, self.w) ** (-1 * t1)) * (self.group.pair_prod(self.v, self.g2) ** (-1 * t3))
# 		return (tt1, tt2, tt3)

# 	def sign(self, sku, m):
# 		(R, alpha) = sku
# 		a = self.group.random(ZR)
# 		cR = ( self.u ** a, ( self.v ** a ) * R )
# 		c1, c2 = cR
# 		r1 = self.group.random(ZR)
# 		r2 = self.group.random(ZR)
# 		r3 = self.group.random(ZR)
# 		calc = self.phi(r1, r2, r3, c1, c2)

# 		# pasar cosas a bytes antes de hash maybe

# 		m_bytes = objectToBytes(m, self.group)
# 		cR_bytes = objectToBytes(cR, self.group)
# 		calc_bytes = objectToBytes(calc, self.group)
# 		z = self.h.hashToZr(m_bytes, cR_bytes, calc_bytes)

# 		t1 = z*a
# 		t2 = z*alpha
# 		t = (z * a, z * alpha, z * a * alpha)
# 		s = (r1 + t[0], r2 + t[1], r3 + t[2])

# 		sigma = (z, s)

# 		return (cR, sigma)

# 	def verify(self, m, cR, sigma):
# 		(c1, c2) = cR
# 		(z, s) = sigma
# 		(r1, r2, r3) = s

# 		calc = self.phi(r1, r2, r3, c1, c2)

# 		t1 = c1 ** z
# 		t2 = 1
# 		t3 = (self.group.pair_prod(self.g1, self.g2) / self.group.pair_prod(c2, self.w)) ** z

# 		rp = (calc[0]/t1, calc[1]/t2, calc[2]/t3)

# 		m_bytes = objectToBytes(m, self.group)
# 		cR_bytes = objectToBytes(cR, self.group)
# 		rp_bytes = objectToBytes(rp, self.group)

# 		hcalc = self.h.hashToZr(m_bytes, cR_bytes, rp_bytes)

# 		return z == hcalc


# def sec_share_gen(servers, group, g, sec_share, share_name, only_val=False):

# 	for p in servers:
# 		p_id = p.get('idx')

# 		z = GROUP.random(ZR)
# 		var_name = 'dkg_z_' + str(p_id)
# 		p.save(var_name, z)
# 		w, v, e0, r, v_feldman = sec_share.share_encode(z, feldman=True)
# 		var_name = 'feldman_v_' + str(p_id)
# 		BROADCAST[var_name] = v_feldman

# 		# sending shares
# 		for i in range(1, N+1):
# 			server = servers[i-1]
# 			var_name = 'dkg_sharing_' + str(p_id) + str(i)
# 			server.save(var_name, w[i])

# 		# broadcast verification values
# 		var_name = 'dkg_v_' + str(p_id)
# 		BROADCAST[var_name] = v


# 	# verifying shares	
# 	for p in servers:
# 		p_id = p.get('idx')
# 		var_name = share_name + str(p_id)
# 		p.save(var_name, (0, 0))

# 		for i in range(1, N+1):

# 			server = servers[i-1]

# 			# for x
# 			w_name = 'dkg_sharing_' + str(i) + str(p_id)
# 			(si, ri) = p.get(w_name)

# 			var_name = 'dkg_v_' + str(i)
# 			v = BROADCAST[var_name]

# 			var_name = 'feldman_v_' + str(i)
# 			v_feldman = BROADCAST[var_name]


# 			verification = sec_share.verify(si, ri, v, p_id)
# 			feldman_verification = sec_share.verify_feldman(si, v_feldman, p_id)

# 			if not verification:
# 				print('Server ' + str(p_id) + ' failed to verify share from server ' + str(i) + ' when generating x')

# 			if not feldman_verification:
# 				print('Server ' + str(p_id) + ' failed to verify share from server ' + str(i) + ' when extracting h')

# 			var_name = share_name + str(p_id)
# 			new_x, new_r = p.get(var_name)
# 			new_x += si
# 			new_r += ri
# 			p.save(var_name, (new_x, new_r))


# 	if only_val:
# 		return servers, None


# 	ver_vals = BROADCAST['feldman_v_1']
# 	h = ver_vals[0]

# 	for i in range(2, N+1):
# 		var_name = 'feldman_v_' + str(i)
# 		ver_vals = BROADCAST[var_name]
# 		h *= ver_vals[0]

# 	return servers, h

# def gen_zero(servers, group, sec_share):
# 	z = group.random(ZR)
# 	zero = z-z

# 	for p in servers:
# 		p_id = p.get('idx')
# 		w, v, e0, r, v_feldman = sec_share.share_encode(zero, feldman=True)
# 		var_name = 'zero_v_' + str(p_id)
# 		BROADCAST[var_name] = v_feldman

# 		for i in range(1, N+1):
# 			server = servers[i-1]
# 			var_name = 'zero_shares_' + str(p_id) + str(i)
# 			server.save(var_name, w[i][0])

# 	for p in servers:
# 		p_id = p.get('idx')

# 		zero_share = 0

# 		for i in range(1, N+1):
# 			w_name = 'zero_shares_' + str(i) + str(p_id)
# 			si = p.get(w_name)

# 			var_name = 'zero_v_' + str(i)
# 			v_feldman = BROADCAST[var_name]

# 			verification = sec_share.verify_feldman(si, v_feldman, p_id)

# 			if not verification:
# 				print('Server ' + str(p_id) + ' failed to verify zero sharing of server ' + str(i))

# 			zero_share += si

# 		var_name = 'zero_share_' + str(p_id)
# 		p.save(var_name, zero_share)

# 	return servers


# def gen_inv_temp(servers, group, g, sec_share, share_name):
# 	servers, gk = sec_share_gen(servers, group, g, sec_share, share_name)

# 	shares = [0]
# 	for p in servers:
# 		p_id = p.get('idx')
# 		var_name = share_name + str(p_id)
# 		s = p.get(var_name)
# 		shares += [s]

# 	y = {group.init(ZR, i):shares[i][0] for i in range(1, len(servers)+1)}
# 	k = sec_share.reconstruct(y)

# 	gk1 = (g ** (k ** -1))

# 	return servers, gk1





# def gen_inv(servers, group, g, sec_share, share_name):
# 	servers, gk = sec_share_gen(servers, group, g, sec_share, share_name)
# 	servers, ga = sec_share_gen(servers, group, g, sec_share, 'a_share_')
# 	servers = gen_zero(servers, group, sec_share)

# 	k_shares = []
# 	a_shares = []
# 	b_shares = []
# 	for p in servers:
# 		p_id = p.get('idx')

# 		var_name = share_name + str(p_id)
# 		ki, aux = p.get(var_name)
# 		k_shares += [ki]

# 		var_name = 'a_share_' + str(p_id)
# 		ai, aux = p.get(var_name)
# 		a_shares += [ai]

# 		var_name = 'zero_share_' + str(p_id)
# 		bi = p.get(var_name)
# 		b_shares += [bi]

# 		# vi = ki * ai + bi

# 		# var_name = 'inv_v_' + str(p_id)
# 		# BROADCAST[var_name] = vi

# 	print(len(k_shares))
# 	ak = sec_share.mult_temp(k_shares, a_shares, N)

# 	for i in range(len(b_shares)):
# 		vi = ak[i] + b_shares[i]
# 		var_name = 'inv_v_' + str(i+1)
# 		BROADCAST[var_name] = vi


	
# 	y = {}

# 	for i in range(1, N+1):
# 		var_name = 'inv_v_' + str(i)
# 		vi = BROADCAST[var_name]
# 		y[group.init(ZR, i)] = vi

# 	mu = sec_share.reconstruct(y)

# 	res = ga ** (mu ** -1)

# 	return servers, res

	

# class Server():
# 	idx = None
# 	x_share = None
# 	skd_share = None
# 	q_share = None
# 	s_share = None
# 	vals = {}

# 	def __init__(self, idx):
# 		self.idx = idx

# 	def set_x(self, val):
# 		self.x_share = val

# 	def set_skd(self, val):
# 		self.skd_share = val

# 	def set_q(self, val):
# 		self.q_share = val

# 	def set_s(self, val):
# 		self.s_share = val

# 	def save(self, name, value):
# 		self.vals[name] = value

# 	def get(self, value):
# 		if value == 'idx':
# 			return self.idx
# 		elif value == 'x_share':
# 			return self.x_share
# 		elif value == 'skd_share':
# 			return self.skd_share
# 		elif value == 'q_share':
# 			return self.q_share
# 		elif value == 's_share':
# 			return self.s_share
# 		else:
# 			return self.vals[value]


# class Accuser():
# 	idx = None
# 	R = None
# 	q = None
# 	alpha = None
# 	vals = {}

# 	def __init__(self, idx):
# 		self.idx = idx

# 	def save(self, name, value):
# 		self.vals[name] = value

# 	def get(self, value):
# 		if value == 'idx':
# 			return self.idx
# 		else:
# 			return self.vals[value]

	

# N = 3
# K = 3

# VALID_ACCUSERS = [Accuser(i) for i in range(0, 10)]
# GROUP = PairingGroup('BN254')

# BROADCAST = {}

# servers = []

# for i in range(1, N+1):
# 	s = Server(i)
# 	servers += [s]

# el_gamal = ElGamal(GROUP)

# g = GROUP.random(G1)
# pedersen_h = GROUP.random(G1)
# sec_share = SecShare(GROUP, g, pedersen_h, K, N, el_gamal)

# g2 = GROUP.random(G2)
# pedersen_h2 = GROUP.random(G2)
# sec_share_g2 = SecShare(GROUP, g2, pedersen_h2, K, N, el_gamal)




# ## INITIALIZE
# valid_accusers = VALID_ACCUSERS
# servers, h = sec_share_gen(servers, GROUP, g, sec_share, 'x_share_')

# pkeg = {'g': g, 'h': h}
# el_gamal.pkeg = pkeg
# sec_share.h = h

# ## accusation, hacer varias
# D = 'persona1'

# rD = GROUP.random(ZR)
# cD = el_gamal.enc_string(rD, D)
# cDd = {'c1': cD[0], 'c2': cD[1]}
# h = Hash(pairingElement=GROUP)
# s = h.hashToZr(D)
# w, v, e0, r = sec_share.share_encode(s)
# es = {'c1': e0, 'c2': v[0]}
# es = (e0, v[0])

# rp = GROUP.random(ZR)
# rpp = GROUP.random(ZR)
# R = g ** rp
# cR = el_gamal.enc(rpp, R)


# ######## testing ######
# shares = [0]
# for p in servers:
# 	p_id = p.get('idx')
# 	var_name = 'x_share_' + str(p_id)
# 	s = p.get(var_name)
# 	shares += [s]

# group = GROUP
# y = {group.init(ZR, 1):shares[1][0], group.init(ZR, 2):shares[2][0], group.init(ZR, 3):shares[3][0]}
# x = sec_share.reconstruct(y)

# el_gamal.skeg = {'x': x}




# ###### DUPLICATES #####
# # ORIGINAL

# h = Hash(pairingElement=GROUP)

# def e_prove(c1, c2, a, r, h):
# 	a1, a2 = a
# 	k = GROUP.random(ZR)
# 	b1 = c1 ** k
# 	b2 = c2 ** k
# 	a1_bytes = objectToBytes(a1, GROUP)
# 	a2_bytes = objectToBytes(a2, GROUP)
# 	b1_bytes = objectToBytes(b1, GROUP)
# 	b2_bytes = objectToBytes(b2, GROUP)
# 	c1_bytes = objectToBytes(c1, GROUP)
# 	c2_bytes = objectToBytes(c2, GROUP)
# 	alpha = h.hashToZr(a1_bytes, a2_bytes, b1_bytes, b2_bytes, c1_bytes, c2_bytes)
# 	beta = alpha * k + r
# 	return (beta, b1, b2)


# def e_verify(c1, c2, pi, a, h):
# 	beta, b1, b2 = pi
# 	a1, a2 = a
# 	a1_bytes = objectToBytes(a1, GROUP)
# 	a2_bytes = objectToBytes(a2, GROUP)
# 	b1_bytes = objectToBytes(b1, GROUP)
# 	b2_bytes = objectToBytes(b2, GROUP)
# 	c1_bytes = objectToBytes(c1, GROUP)
# 	c2_bytes = objectToBytes(c2, GROUP)
# 	alpha = h.hashToZr(a1_bytes, a2_bytes, b1_bytes, b2_bytes, c1_bytes, c2_bytes)
# 	ver1 = c1 ** beta == a1 * (b1 ** alpha)
# 	ver2 = c2 ** beta == a2 * (b2 ** alpha)
# 	res = ver1 and ver2
# 	return res

# # def exp_share(p, base, share):
# # 	val = base ** share
# # 	p.set_exp(val)


# def dist_dec(c1, c2):
# 	threads = list()
# 	for p in servers:
# 		x_share = p.get('x_share')
# 		t = threading.Thread(target=exp_share, args=(c1, x_share))
# 		threads.append(t)
# 		t.start()

# 	for thread in enumerate(threads):
# 		threads.join()

# 	# di = SecShare.Exp(c1, x)
# 	# d = SecShare.Reconstruc(di)
# 	# return c2/d
# 	return 0

# def msgrand1(c1, c2, p):
# 	p_id = p.get('idx')
# 	ri = GROUP.random(ZR)
# 	ai = (c1 ** ri, c2 ** ri)
# 	pii = e_prove(c1, c2, ai, ri)
# 	var_name = 'ai_' + str(p_id)
# 	BROADCAST[var_name] = ai
# 	var_name = 'pii_' + str(p_id)
# 	BROADCAST[var_name] = pii

# def msgrand2(c1, c2, p):
# 	p_id = p.get('idx')

# 	for s in servers:
# 		s_id = s.get('idx')
# 		var_name = 'ai_' + str(s_id)
# 		asi = BROADCAST[var_name]
# 		var_name = 'pii_' + str(s_id)
# 		pisi = BROADCAST[var_name]
# 		ver = e_verify(c1, c2, pisi, asi)
# 		if not ver:
# 			print('Server ' + str(p_id) + ' failed to verify share from server ' + str(s_id) + ' during Equal')


# def msgrand(c):
# 	threads = list()
# 	c1, c2 = c
# 	for p in servers:
# 		t = threading.Thread(target=msgrand1, args=(c1, c2, p))
# 		threads.append(t)
# 		t.start()

# 	for thread in enumerate(threads):
# 		threads.join()

# 	for p in servers:
# 		t = threading.Thread(target=msgrand2, args=(c1, c2, p))
# 		threads.append(t)
# 		t.start()

# 	for thread in enumerate(threads):
# 		threads.join()
		
# 	a1 = 1
# 	a2 = 1
# 	for i in range(1, N+1):
# 		var_name = 'ai_' + str(i)
# 		ai = BROADCAST[var_name]
# 		ai1, ai2 = ai
# 		a1 *= ai1
# 		a2 += ai2

# 	cp = (a1, a2)
# 	m = dist_dec(cp)


# def equalsfunc(ca, cb):
# 	c1a, c2a = ca
# 	c1b, b2b = cb
# 	c1 = c1a / c1b
# 	c2 = c2a / c2b
# 	c = (c1, c2)
# 	return msgrand(c) == 1


# esp = 0
# crp = 0
# for acc in accusations:
# 	cr, es, cd = acc
# 	eq1 = equalsfunc(crp, cr)
# 	eq2 = equalsfunc(esp, es)
# 	if eq1 or eq2:
# 		print('duplicate')
# 		break
# print('not duplicate')




# # DVRF

# # def dvrf_calc(in_name, j=None):
# # 	for p in servers:
# # 		skdi = p.get('skd_share')
# # 		in_share = p.get(in_name)
# # 		t1 = skdi + in_share
# # 		if j != None:
# # 			t1 += j

		
# # 	servers, aux = sec_share_gen(servers, GROUP, g, sec_share, 'r_share_', only_val=True)

# # 	for p in servers:
# # 		t2 = SecShare.Mult(r1, r)
# # 		exp = (t2 ** -1) * r
# # 		base = GROUP.pair_prod(g, g)
# # 		res = SecShare.Exp(base, exp)
		

# # # duplicate revision
# # djp_shares = dvrf_calc('s_share', j)
# # djp = sec_share.reconstruct_exp(djp_shares)
# # sq_share = s_share + q_share
# # p_shares = dvrf_calc('sq_share')
# # p = sec_share.reconstruct_exp(p_shares)
# # if p in unique_accs:
# # 	output 'dpuplicate'
# # else:
# # 	output 'not duplicate'



