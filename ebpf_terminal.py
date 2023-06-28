import os
import time
import paramiko as pm

class ebpfTerminal:
	def __init__(self, connect_info):
		self.connect_info = connect_info
		
		self.address = self.connect_info["address"]
		self.port = self.connect_info["port"]
		self.username = self.connect_info["username"]
		self.password = self.connect_info["password"]
		self.hostname = self.connect_info["hostname"]

		self.client = pm.SSHClient()
		self.channel = None

		self.__preprocess__()

	def __waitstream__(self):
		time.sleep(0.1)

		outdata = ""
		errdata = ""

		while self.channel.recv_ready():
			outdata += str(self.channel.recv(1000))
		while self.channel.recv_stderr_ready():
			errdata += str(self.channel.recv_stderr(1000))

		return outdata, errdata
	
	def __preprocess__(self):
		self.client.load_system_host_keys()
		self.client.load_host_keys(os.path.expanduser("~/.ssh/known_hosts"))
		self.client.set_missing_host_key_policy(pm.AutoAddPolicy())
		self.client.connect(hostname = self.address, port = self.port, username = self.username, password = self.password)
		self.channel = self.client.invoke_shell()

	def __mainprocess__(self, command):
		self.channel.send(command)
		self.channel.send("\n")

		outdata, errdata = self.__waitstream__()
#		outdata = outdata.split("\\r\\n")
#		for data in outdata:
#			print(data)
		if errdata != "": 
			return False

		return True


