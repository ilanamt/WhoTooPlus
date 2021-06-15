from charm.toolbox.pairinggroup import ZR
from tqdm.contrib.concurrent import thread_map

class PrivatePoly():

	def __init__(self, sec_share, eg, pkeg):
		self.sec_share = sec_share
		self.eg = eg
		self.pkeg = pkeg

	def subtract(self, eF, eG):
		eH = []
		for i in range(len(eF)):
			eHi = (eF[i][0] * (eG[i][0] ** -1), eF[i][1] * (eG[i][1] ** -1))
			eH += [eHi]

		return eH

	def differentiate(self, eF, n):
		d = len(eF)-1
		eH = [(0,0)]*(d-n+1)
		for i in range(n, d+1):
			c = 1
			for j in range(i-n+1, i+1): # precalculate this
				c *= j
			eH[i-n] = (eF[i][0] ** c, eF[i][1] ** c)

		return eH

	def multiply(self, eF, R):
		d = len(eF) - 1
		q = len(R) - 1
		eg0 = self.pkeg['g'] ** 0
		eG = [self.eg.enc(self.pkeg, eg0)] * (d + q + 1)
		for i in range(0, d+1):
			for j in range(0, q+1):
				eG[i+j] = (eG[i+j][0] * (eF[i][0] ** R[j]), eG[i+j][1] * (eF[i][1] ** R[j]))
		return eG

	# s in temp1
	def multiply_linear(self, servers, eF):
		self.sec_share.servers = servers
		d = len(eF) - 1
		eg0 = self.eg.enc(self.pkeg, self.pkeg['g'] ** 0)
		eG = [eg0] + eF
		eH = []
		for i in range(0, d+1):
			eHi = self.sec_share.expRR(eF[i])
			eH += [eHi]
		eH += [eg0]

		# print((type(eG)))
		# print(type(eH))

		return self.subtract(eG, eH)

	# s in temp1
	def zero_test(self, servers, eF):
		self.sec_share.servers = servers
		d = len(eF)-1
		self.sec_share.gen() # r1 en temp2
		def temp_func1(p):
			p.temp6 = p.temp1 # s en temp6
			p.temp1 = p.temp2 # r1 en temp1
			p.temp7 = [p.temp2]

		thread_map(temp_func1, self.sec_share.servers, leave=False)

		self.sec_share.invert() # t = r^-1 en temp3
		def temp_func2(p):
			p.temp7 = [p.temp3] + p.temp7 # temp7 = [t, r1]
			p.temp1 = p.temp7[1]

		thread_map(temp_func2, self.sec_share.servers, leave=False)

		for i in range(2, d+1):
			def temp_func3(p):
				p.temp2 = p.temp7[i-1]
			
			thread_map(temp_func3, self.sec_share.servers, leave=False)
			
			self.sec_share.mult()
			def temp_func4(p):
				p.temp7 += [p.temp3]

			thread_map(temp_func4, self.sec_share.servers, leave=False)

		def temp_func5(p):
			p.temp1 = p.temp7[0] # t en temp1
			p.temp2 = p.temp6 # s en temp2

		thread_map(temp_func5, self.sec_share.servers, leave=False)

		self.sec_share.mult() # x = s*t en temp3
		x_shares = {}
		for p in self.sec_share.servers:
			dk = self.sec_share.group.init(ZR, p.id)
			x_shares[dk] = p.temp3

		x = self.sec_share.reconstruct(x_shares)
		# print('eF', eF)
		# print('ef0', eF[0])
		cy = eF[0]
		# mv = self.sec_share.dist_dec(servers, cy)
		# print(mv)


		for i in range(1, d+1):
			def temp_func6(p):
				p.temp1 = (x ** i) * p.temp7[i]
			
			thread_map(temp_func6, self.sec_share.servers, leave=False)
			cyi = self.sec_share.expRR(eF[i])
			cy = (cy[0] * cyi[0], cy[1] * cyi[1])
			# mv = self.sec_share.dist_dec(servers, cy)
			# print(mv)

		# mv = self.sec_share.dist_dec(servers, cy)
		# print(mv)
		res = self.sec_share.msg_rand(cy)
		g0 = self.pkeg['g'] ** 0
		return (res == g0)

		



			