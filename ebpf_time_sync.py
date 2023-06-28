import threading as th
import time

import ebpf_terminal

class ebpfTimesync:
	def __init__(self, ebpf_conf, ebpf_python):
		self.ebpf_conf = ebpf_conf
		self.connect_info = self.ebpf_conf.connect_info
		self.management_server_info = self.ebpf_conf.management_server_info
		self.redis_info = ebpf_conf.redis_info
		self.ebpf_python = ebpf_python

		self.terminal = []
		self.continuing = True
	
	def __preprocess0__(self):
		key1 = "servers"

		for connect_info in self.connect_info[key1]:
			if connect_info.get("iscontainer") != None: continue
			et = ebpf_terminal.ebpfTerminal(connect_info)
			et.__preprocess__()

			command = ""
			if connect_info.get("isvm") == None:
				command = "sudo ./ebpf_program_host/util/exec_kill.sh"
			else:
				command = "sudo ./ebpf_program_vm/util/exec_kill.sh"

			et.__mainprocess__(command)
			time.sleep(0.1)
			et.__mainprocess__(connect_info["password"])
			time.sleep(0.1)
		
	def __preprocess1__(self):
		key1 = "servers"

		for connect_info in self.connect_info[key1]:
			if connect_info.get("iscontainer") != None: continue
			et = ebpf_terminal.ebpfTerminal(connect_info)
			et.__preprocess__()

			command = ""
			if connect_info.get("isvm") == None:
#				command = "sudo python3 ~/ebpf_program_host/time_sync/ebpf_main.py " 
				command = "sudo python3 ~/ebpf_program_vm/time_sync/ebpf_main.py "
			else:
				command = "sudo python3 ~/ebpf_program_vm/time_sync/ebpf_main.py "

			command += "--redis_host " + self.redis_info["host"] + " --redis_port " + str(self.redis_info["port"]) + " --redis_key " + str(connect_info["metadata_key"])

			print(command)
			et.__mainprocess__(command)
			time.sleep(0.1)
			et.__mainprocess__(connect_info["password"])
			time.sleep(0.1)

			self.terminal.append(et)

	def __preprocess2__(self):
		command = "start"
		while self.continuing:
			for et in self.terminal:
				et.__mainprocess__(command)	
		
		command = "end"
		for et in self.terminal:
			et.__mainprocess__(command)

	def __mainprocess__(self):
		self.ebpf_python.__main__()

########################################################################
	def __main__(self):
		print("ebpf_time_sync process start")
		self.__preprocess0__()
		self.__preprocess1__()

		thread = th.Thread(target = self.__preprocess2__, args = ())
		thread.start()

		self.__mainprocess__()
		self.continuing = False

		thread.join()

		



			

	
	
