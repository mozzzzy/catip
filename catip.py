import sys


class Ipv4Obj:

	def __init__(self, ip_str, net_mask_str):

		# convert net_mask_str. e.g. convert from '0xffffff00' to '255.255.255.0'
		if len(net_mask_str) > 2 and net_mask_str[:2] == '0x':
			net_mask_str = Ipv4Obj.getDecAddrFromHex(net_mask_str)

		# convert net_mask_str. e.g. convert from '24' to '255.255.255.0'
		elif net_mask_str.isnumeric():
			net_mask_str = Ipv4Obj.getDecAddrFromDec(net_mask_str)


		##########################
		# create ip address info #
		##########################
		# create self.visible_ip_str . e.g. '192.168.3.56'
		self.visible_ip_str = ip_str

		# create list self.each_ip_str . e.g. ['192', '168', '3', '56']
		self.each_ip_str = Ipv4Obj.getEachIpStr(self.visible_ip_str)

		# create list self.each_bin_ip_str . e.g. ['11000000', '10101000', '00000011', '00111000']
		self.each_bin_ip_str = Ipv4Obj.getEachBinIpStr(self.visible_ip_str)

		# create string self.visible_bin_ip_str . e.g. '11000000.10101000.00000011.00111000'
		self.visible_bin_ip_str = Ipv4Obj.getVisibleBinIpStr(self.visible_ip_str)


		########################
		# create net mask info #
		########################
		# create self.visible_net_mask_str . e.g. '255.255.255.0'
		self.visible_net_mask_str = net_mask_str

		# create list self.each_net_mask_str . e.g. ['255', '255', '255', '0']
		self.each_net_mask_str = Ipv4Obj.getEachIpStr(self.visible_net_mask_str)

		# create list self.each_bin_net_mask_str . e.g. ['11111111', '11111111', '11111111', '00000000']
		self.each_bin_net_mask_str = Ipv4Obj.getEachBinIpStr(self.visible_net_mask_str)

		# create string self.visible_bin_net_mask_str . e.g. '11111111.11111111.11111111.00000000'
		self.visible_bin_net_mask_str = Ipv4Obj.getVisibleBinIpStr(self.visible_net_mask_str)


		###############################
		# create network address info #
		###############################
		# create list self.each_bin_net_addr_str . e.g. ['11000000', '10101000', '00000011', '00000000'] 
		self.each_bin_net_addr_str = Ipv4Obj.getEachBinNetAddrStr(self.visible_ip_str, self.visible_net_mask_str)

		# create string self.visible_bin_net_addr_str . e.g. '11000000.10101000.00000011.00000000'
		self.visible_bin_net_addr_str = Ipv4Obj.getVisibleBinNetAddrStr(self.visible_ip_str, self.visible_net_mask_str)

		# create list self.each_net_addr_str . e.g. ['192', '168', '3', '0']
		self.each_net_addr_str = Ipv4Obj.getEachNetAddrStr(self.visible_ip_str, self.visible_net_mask_str)

		# create string self.visible_net_addr_str . e.g. '192.168.3.0'
		self.visible_net_addr_str = Ipv4Obj.getVisibleNetAddrStr(self.visible_ip_str, self.visible_net_mask_str)


	@classmethod
	def getDecAddrFromHex(cls, visible_hex):
		raw_dec = int(visible_hex, 16)
		raw_bin = bin(raw_dec)[2:]

		each_8bit = []
		for pc in range(4):
			each_8bit.append(raw_bin[(8*pc):(8*(pc+1))])

		decAddr = ''
		for e8 in each_8bit:
			each_dec = int(e8,2);
			decAddr += (str(each_dec) + '.')

		decAddr = decAddr[:-1]
		return decAddr
	

	@classmethod
	def getDecAddrFromDec(cls, visible_dec):
		raw_bin = ''
		for val in range(int(visible_dec)):
			raw_bin += '1'

		for val in range(32 - int(visible_dec)):
			raw_bin += '0'

		each_8bit = []
		for pc in range(4):
			each_8bit.append(raw_bin[(8*pc):(8*(pc+1))])

		decAddr = ''
		for e8 in each_8bit:
			each_dec = int(e8,2);
			decAddr += (str(each_dec) + '.')

		decAddr = decAddr[:-1]
		return decAddr
	

	@classmethod
	def getEachIpStr(cls, visible_ip_str):
		return visible_ip_str.split('.')


	@classmethod
	def getEachBinIpStr(cls, visible_ip_str):
		each_ip_str = cls.getEachIpStr(visible_ip_str)
		each_bin_ip_str = []
		for eis in each_ip_str:
			each_bin_ip_str_variable_length = bin(int(eis))[2:]

			for zc in range(8 - len(each_bin_ip_str_variable_length)):
				each_bin_ip_str_variable_length = '0' + each_bin_ip_str_variable_length
	
			each_bin_ip_str.append(each_bin_ip_str_variable_length)

		return each_bin_ip_str


	@classmethod
	def getVisibleBinIpStr(cls, visible_ip_str):
		each_bin_ip_str = cls.getEachBinIpStr(visible_ip_str)

		visible_bin_ip_str = ''
		for ebis in each_bin_ip_str:
			visible_bin_ip_str += (ebis + '.')
		visible_bin_ip_str = visible_bin_ip_str[:-1]

		return visible_bin_ip_str


	@classmethod
	def getEachBinNetAddrStr(cls, visible_ip_str, visible_net_mask_str):
		each_bin_ip_str = cls.getEachBinIpStr(visible_ip_str)
		each_bin_net_mask_str = cls.getEachBinIpStr(visible_net_mask_str)

		each_bin_net_addr_str = []		
		for ebis, ebnms in zip(each_bin_ip_str, each_bin_net_mask_str):
			ebnas = ''
			for each_num in range(len(ebis)):
				ebnas += str(int(ebis[each_num:each_num+1]) & int(ebnms[each_num:each_num+1]))

			each_bin_net_addr_str.append(ebnas)

		return each_bin_net_addr_str


	@classmethod
	def getVisibleBinNetAddrStr(cls, visible_ip_str, visible_net_mask_str):
		each_bin_net_addr_str = cls.getEachBinNetAddrStr(visible_ip_str, visible_net_mask_str)

		visible_bin_net_addr_str = ''
		for ebnas in each_bin_net_addr_str:
			visible_bin_net_addr_str += (ebnas + '.')
		visible_bin_net_addr_str = visible_bin_net_addr_str[:-1]

		return visible_bin_net_addr_str


	@classmethod
	def getEachNetAddrStr(cls, visible_ip_str, visible_net_mask_str):
		each_bin_net_addr_str = cls.getEachBinNetAddrStr(visible_ip_str, visible_net_mask_str)
		each_net_addr_str = []
		for ebnas in each_bin_net_addr_str:
			each_net_addr_str.append(int(ebnas,2))
		
		return each_net_addr_str


	@classmethod
	def getVisibleNetAddrStr(cls, visible_ip_str, visible_net_mask_str):
		each_net_addr_str = cls.getEachNetAddrStr(visible_ip_str, visible_net_mask_str)
	
		visible_net_addr_str = ''
		for enas in each_net_addr_str:
			visible_net_addr_str += (str(enas) + '.')
		visible_net_addr_str = visible_net_addr_str[:-1]

		return visible_net_addr_str


	def v4print(self):
		print('[ip address]')
		print('\tip address          : ' + self.visible_ip_str)
		print('\tbin ip address      : ' + self.visible_bin_ip_str)
		print('[network mask]')
		print('\tnet mask            : ' + self.visible_net_mask_str)
		print('\tbin net mask        : ' + self.visible_bin_net_mask_str)
		print('[network address]')
		print('\tnetwork address     : ' + self.visible_net_addr_str)
		print('\tbin network address : ' + self.visible_bin_net_addr_str)


def printUsage():
	print('Usage: $ python catip <ip address> <netmask>')


if __name__ == '__main__':

	args = sys.argv

	if len(args) == 3:

		ip_address = args[1]
		net_mask = args[2]

		ipv4_obj = Ipv4Obj(str(ip_address), str(net_mask))
		ipv4_obj.v4print()

	else:
		printUsage()


