from bcc import BPF
import redis
import json
import ctypes
import multiprocessing
import logging

import ebpf_code
import ebpf_conf
import ebpf_database

class ebpfPython:
	def __init__(self):
		self.ec = ebpf_code.ebpfCode()
		self.code = self.ec.__main__()
		self.ef = ebpf_conf.ebpfConf()
		self.args = self.ef.__main__()
		self.ed = ebpf_database.ebpfDatabase(self.args)
		self.ed.__main__()

		self.rd = redis.StrictRedis(host = self.args.redis_host, port = self.args.redis_port, db = 0)
		self.rd_key = self.args.redis_key

		self.b = BPF(text = self.code, cflags = ["-DNUM_CPUS=%d" % multiprocessing.cpu_count()])
		self.t_sampling_size = self.b.get_table("sampling_size")
		self.b["event_ringbuf"].open_ring_buffer(self.__event_ringbuf_callback__)

		self.func_name = ["sock_sendmsg", "tcp_sendmsg", "ip_local_out", "sock_recvmsg", "tcp_v4_rcv", "ip_local_deliver"]

		self.metadata = None
		self.sampling_size = None
	
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

		self.sampling_size = self.rd.get("sampling").decode("utf-8")
		self.sampling_size = dict(json.loads(self.sampling_size))
	
	def __set_metadata__(self):
		key = 1
		self.t_sampling_size[ctypes.c_uint8(key)] = ctypes.c_uint32(self.sampling_size["size"])

################################################################################
	def __attach_function__(self):
		for func_name in self.func_name:
			if func_name.find("sock") != -1:
				self.b.attach_kprobe(event = func_name, fn_name = "___" + func_name)
				self.b.attach_kretprobe(event = func_name, fn_name = "__" + func_name)
			else:
				self.b.attach_kprobe(event = func_name, fn_name = "__" + func_name)
	
	def __event_ringbuf_callback__(self, ctx, data, size):
		event_data = self.b["event_ringbuf"].event(data)
		self.ed.__insert1__(event_data)
		self.ed.__insert2__(event_data)
	
################################################################################
	def __main__(self):
		self.__get_metadata__()
		self.__set_metadata__()
		self.__attach_function__()

		while True:
			try:
				self.b.ring_buffer_consume()
			except:
				logging.exception("message")
				return
