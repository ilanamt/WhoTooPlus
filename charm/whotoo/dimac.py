from charm.toolbox.pairinggroup import PairingGroup,ZR

class Dimac():
	sec_share = None

	def __init__(self, sec_share):
		self.sec_share = sec_share

	def tag(self, servers, tau, user):
		self.sec_share.servers = servers
		self.sec_share.gen() # shares de j en temp2
		w, v, e0, rr = self.sec_share.share_encode(tau)

		for p in self.sec_share.servers:
			pid = p.id
			p.temp1 = w[pid][0] + p.temp2
			user.da_shares[pid-1] = p.temp2

		# user does this
		j_shares = {self.sec_share.group.init(ZR, i): user.da_shares[i-1] for i in range(1, len(servers)+1)}
		j = self.sec_share.reconstruct(j_shares)
		
		
		user = self.sec_share.diprf(user)

		# user does this
		dj = 1
		for i in range(1, len(self.sec_share.servers)+1):
			pid = self.sec_share.group.init(ZR, i)
			dj *= (user.da_shares[i-1] ** self.sec_share.coeffs[pid])

		return (j, dj)


	# shares of tau in temp1
	def verify(self,servers, dj, j):
		self.sec_share.servers = servers
		w, v, e0, rr = self.sec_share.share_encode(j)
		for p in self.sec_share.servers:
			pid = p.id
			p.temp1 = p.temp1 + w[pid][0]
		
		djp = self.sec_share.diprf()
		ver = (dj == djp)

		return ver