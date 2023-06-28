from bcc import BPF
import sys
import redis
import ctypes
import json
import multiprocessing
import logging

import ebpf_conf
import ebpf_code

class ebpfPython:
	def __init__(self):
		self.ec = ebpf_conf.ebpfConf()
		self.args = self.ec.__main__()

		self.ex = ebpf_code.ebpfCode()
		self.code = self.ex.__main__()

		self.b = BPF(text = self.code, cflags = ["-w", "-std=gnu99", "-DNUM_CPUS=%d" % multiprocessing.cpu_count()])
		self.t_addr = self.b.get_table("t_addr")

		self.metadata = None

		self.rd = redis.StrictRedis(host = self.args.redis_host, port = self.args.redis_port, db = 0)
		self.rd_key = self.args.redis_key
	
	def __change_addr__(self, addr):
		addr = addr.split(".")
		addr_bin = ""
		for digit in addr:
			addr_temp = bin(int(digit))[2:]
			addr_temp = addr_temp.zfill(8)
			addr_bin += addr_temp

		addr_bin = addr_bin[24:32] + addr_bin[16:24] + addr_bin[8:16] + addr_bin[0:8]
		addr_bin = "0b" + addr_bin
		addr_int = int(addr_bin, 2)
		return addr_int

	def __get_metadata__(self):
		self.metadata = self.rd.get(self.rd_key).decode("utf-8")
		self.metadata = dict(json.loads(self.metadata))
	
	def __set_metadata__(self):
		key = 1
		addr = self.__change_addr__(self.metadata["address"])
		self.t_addr[ctypes.c_uint8(key)] = ctypes.c_uint32(addr)
	
###########################################################################
	def __attach_function__(self):
		in_fn = self.b.load_func("syncTimeProtocol", BPF.XDP)
		eths = self.metadata["eth"]

		for eth in eths:
			self.b.attach_xdp(eth, in_fn, 0)
	
	def __detach_function__(self):
		eths = self.metadata["eth"]

		for eth in eths:
			self.b.remove_xdp(eth, 0)

	def __poll_ebpf_event__(self):
		try:
			self.b.perf_buffer_poll(timeout = 1)
		except:
			logging.exception("message")

##########################################################################
	def __main__(self):
		self.__get_metadata__()
		self.__set_metadata__()
		
		self.__attach_function__()

		while True:
			command = input()
			if command == "end": break
			self.__poll_ebpf_event__()

		self.__detach_function__()

		print("termination", file = sys.stdout)
		print("termination", file = sys.stderr)



