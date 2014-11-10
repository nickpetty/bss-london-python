import socket
import struct
import re

class Blu:
	s = ''
	TCP_IP = None
	s = None
	def __init__(self, ip):
		TCP_IP = ip #'192.168.1.100'
		TCP_PORT = 1023
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		#print 'Connecting'
		self.s.connect((TCP_IP, TCP_PORT))
		#print 'Connected'

	def subscribePercent(self, node, vdevice, obj, sv):
		di = '8e'
		# node
		# vdevice
		# object id
		# sv
		data = '00000000'

		packet = str(di) + str(node) + str(vdevice) + str(obj) + str(sv) + str(data)
		packet = str('02') + self.specialChar(packet + self.checksum(packet), 0) + str('03')
		#print packet + ' ' + str(len(packet))

		self.s.send(str(packet.decode('hex')))
		#print 'Subscribed'
		#print 'Waiting for data'

		while 1:
			# Receive message - Encode as hex - Remove 1st 22 char - Send to specialChar function -
			# Capture 1st 8 returned chars - Decode as hex - Unpack signed 32-bit big-endian int into 'long int' -
			# Divide by 65536 - round to two decimal points
			yield round(float(struct.unpack('>l', self.specialChar(self.s.recv(2048).encode('hex')[24:], 1)[:8].decode('hex'))[0])/65536, 2)

		self.s.close()

	def subscribeRaw(self, node, vdevice, obj, sv):
		di = '89'
		data = '00000000'
		packet = str(di) + str(node) + str(vdevice) + str(obj) + str(sv) + str(data)
		packet = str('02') + self.specialChar(packet + self.checksum(packet), 0) + str('03')

		self.s.send(str(packet.decode('hex')))
		#print 'Subscribed'
		#print 'Waiting for data'

		while 1:
			yield int(self.s.recv(2048).encode('hex')[24:][:8]) * 1

	def specialChar(self, subMsg, reverse):
		subs = {'02':'1B82', '03':'1B83', '06':'1B86', '15':'1B95', '1B':'1B9B'}
		subAry = re.findall('..',subMsg) # Break data string into array of twos
		#print subAry
		if reverse == 0:
			pos = 0
			for byte in subAry:
				for key, value in subs.items():
					if key.lower() == byte.lower():
						#print 'found ' + byte + ' at position ' + str(pos)
						#print 'replacing with ' + value
						subAry[pos] = value
				pos += 1

			return "".join(subAry)

		elif reverse == 1:
			#print 'reverse equaled 1'
			pos = 0
			#print 'received byte array ' + str(subAry)

			for byte in subAry:
				#print 'checking byte ' + byte
				for key, value in subs.items():
					if value[:2].lower() == byte.lower(): #if first two char of the value matches the current byte...
						if value[2:].lower() == subAry[pos+1]:
							#print 'found byte ' + byte
							subAry[pos] = key #replace with key
							#print str(subAry)
							#print 'replaced byte with ' + key
							#print 'removing ' + str(subAry[pos+1])
							subAry.pop(pos+1) #remove byte in next position.
							#print str(subAry)
				pos += 1

			#print 'returning byte string ' + "".join(subAry)
			return "".join(subAry)

	def checksum(self, packet):
		#print 'Packet received: ' + packet
		#print 'length: ' + str(len(packet))
		checksum = 0
		for byte in packet.decode('hex'):
			checksum ^= ord(byte)

		#print 'Checksum: ' + hex(checksum)
		return str(hex(checksum)).replace('0x','')

	def setPercent(self, node, vdevice, obj, sv, percent):
		di = '8d'
		#addressData = '0x8D 0x1E 0x19 0x03 0x00 0x01 0x01 0x00 0x00'.replace('0x','').replace(' ','')
		addressData = str(di) + str(node) + str(vdevice) + str(obj) + str(sv)

		#format message data
		msgData = hex(int(percent) * 65536).replace('0x', '')
		if msgData == '0':
			msgData = '000000'
		#msgData = float(percent) * 65536
		#print hex(struct.unpack('<I', struct.pack('<f', msgData))[0])

		#msgData = hex(msgData)
		if len(msgData) == 5:
			msgData = '0' + str(msgData)
		msgData = str('00') + str(msgData)

		#create checksum
		chkSum = self.checksum(addressData + msgData)
		chkSum = self.specialChar(chkSum, 0) #check if checkSum is special character

		#sub special characters
		addressData = self.specialChar(addressData, 0)
		msgData = self.specialChar(msgData, 0)

		#format final message with STX (02) and ETX (03)
		packet = str('02') + str(addressData) +  str(msgData) + str(chkSum) + str('03')
		#print packet + ' ' + str(len(packet))

		self.s.send(packet.decode('hex'))

	def setState(self, node, vdevice, obj, sv, state):
		di = '88'
		addressData = str(di) + str(node) + str(vdevice) + str(obj) + str(sv)
		#addressData = '0x88 0x1E 0x19 0x03 0x00 0x01 0x01 0x00 0x01'.replace('0x','').replace(' ','')
		msg = str('000000') + str(hex(int(state))).replace('0x','0')


		chkSum = self.specialChar(self.checksum(addressData + msg),0)
		addressData = self.specialChar(addressData, 0)

		packet = '02' + addressData + str(msg) + chkSum + '03'
		#print packet
		self.s.send(packet.decode('hex'))

#blu = Blu('192.168.1.100')
#for x in blu.subscribeRaw('1e19','03','000101', '0001'):
#	print x
#for x in blu.subscribePercent('1e19','03','000101','0000'):
#	print x
#blu.setPercent('1e19', '03', '000101', '0000', '75')
#blu.setState('1e19', '03', '000103', '0002', '1')
