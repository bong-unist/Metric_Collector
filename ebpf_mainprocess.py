import time
import ebpf_terminal

class ebpfMainprocess:
	def __init__(self, ebpf_conf):
		self.ebpf_conf = ebpf_conf
		self.connect_info = self.ebpf_conf.connect_info
		self.redis_info = self.ebpf_conf.redis_info

		self.terminals = []
		
	def __ebpf_program_start__(self):
		key1 = "servers"

		for connect_info in self.connect_info[key1]:
			if connect_info.get("iscontainer") != None: continue
			et = ebpf_terminal.ebpfTerminal(connect_info)
			et.__preprocess__()

			command = ""
			if connect_info.get("isvm") == None:
				command = "sudo python3 ~/ebpf_program_vm/metric_measure_vm/ebpf_main.py "
#				command = "sudo python3 ~/ebpf_program_host/metric_measure/ebpf_main.py "
			else:
				command = "sudo python3 ~/ebpf_program_vm/metric_measure_vm/ebpf_main.py "

			command += "--redis_host " + self.redis_info["host"] + " --redis_port " + str(self.redis_info["port"]) + " --redis_key " + str(connect_info["metadata_key"])

			print(command)

			et.__mainprocess__(command)
			time.sleep(0.1)
			et.__mainprocess__(connect_info["password"])
			time.sleep(0.1)

			self.terminals.append(et)

#########################################################################
	def __main__(self):
		print("ebpf program start")
		self.__ebpf_program_start__()




		
