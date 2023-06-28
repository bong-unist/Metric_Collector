from bcc import BPF
import os
import redis
import time
import json
import ctypes
import logging
import multiprocessing
import threading as th
from queue import Queue
from collections import defaultdict

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
		self.t_sampling_port = self.b.get_table("sampling_port")
		self.b["event_ringbuf"].open_ring_buffer(self.__event_ringbuf_callback__)

		self.func_name = ["sock_sendmsg", "tcp_v4_send_check", "ip_finish_output2", "dev_queue_xmit", "sock_recvmsg", "tcp_v4_rcv", "ip_local_deliver", "netif_receive_skb", "kernel_sendpage", "tcp_sendpage", "__netif_receive_skb_core", "virtqueue_add_outbuf"]

		self.metadata = None
		self.sampling_size = None

		self.ports = multiprocessing.Queue()
		self.pair_key = multiprocessing.Queue()
		self.queue = multiprocessing.Queue()

		self.func_type = defaultdict()
		self.func_type["sock_sendmsg"] = 0
		self.func_type["kernel_sendpage"] = 0
		self.func_type["tcp_sendmsg"] = 0
		self.func_type["tcp_sendpage"] = 0
		self.func_type["sock_recvmsg"] = 1
		self.func_type["tcp_recvmsg"] = 1
		self.func_type["__tcp_transmit_skb"] = 2
		self.func_type["tcp_v4_send_check"] = 2
		self.func_type["tcp_v4_rcv"] = 4
		self.func_type["ip_finish_output2"] = 4
		self.func_type["ip_local_out"] = 4
		self.func_type["dev_queue_xmit"] = 4
		self.func_type["virtqueue_add_outbuf"] = 4
		self.func_type["ip_local_deliver"] = 4
		self.func_type["netif_receive_skb"] = 4
		self.func_type["__netif_receive_skb_core"] = 4
		
		self.attach_pos_enter = set()
		self.attach_pos_enter.add(2); self.attach_pos_enter.add(4)
		self.attach_pos_exit = set()
		self.attach_pos_exit.add(3); self.attach_pos_exit.add(5)
		self.attach_pos_enter_exit = set()
		self.attach_pos_enter_exit.add(0); self.attach_pos_enter_exit.add(1)
	
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

		for port in self.sampling_size["ports"]:
			self.t_sampling_port[ctypes.c_uint16(port)] = ctypes.c_uint8(1)

		for port in range(5001, 5002):
			self.t_sampling_port[ctypes.c_uint16(port)] = ctypes.c_uint8(1)
		
		for port in range(80, 81):
			self.t_sampling_port[ctypes.c_uint16(port)] = ctypes.c_uint8(1)

		for port in range(8050, 8051):
			self.t_sampling_port[ctypes.c_uint16(port)] = ctypes.c_uint8(1)

		for port in range(20, 21):
			self.t_sampling_port[ctypes.c_uint16(port)] = ctypes.c_uint8(1)

################################################################################
	def __attach_function__(self):
		for func_name in self.func_name:
			try:
				if self.func_type[func_name] in self.attach_pos_enter:
					self.b.attach_kprobe(event = func_name, fn_name = "___" + func_name)
				elif self.func_type[func_name] in self.attach_pos_exit:
					self.b.attach_kprobe(event = func_name, fn_name = "___" + func_name)
					self.b.attach_kretprobe(event = func_name, fn_name = "____" + func_name)
				elif self.func_type[func_name] in self.attach_pos_enter_exit:
					self.b.attach_kprobe(event = func_name, fn_name = "___" + func_name)
					self.b.attach_kretprobe(event = func_name, fn_name = "____" + func_name)
			except:
				pass
	
	def __event_ringbuf_callback__(self, ctx, data, size):
		event_data = self.b["event_ringbuf"].event(data)
		self.ed.__insert1__(event_data, self.queue, self.ports, self.pair_key)

	def __metric_callback__(self, args, port_queue, pair_key_queue):
		ed = ebpf_database.ebpfDatabase(args)
		ed.__main__()

		ports = set()
		pair_key = defaultdict()

		while True:
			while port_queue.qsize() > 0: ports.add(port_queue.get())
			while pair_key_queue.qsize() > 0:
				data = pair_key_queue.get()
				pair_key[data[0]] = data[1]
			
			ed.__insert2__(ports, pair_key)
			time.sleep(0.1)

	def __update_callback__(self, queue, args):
		ed = ebpf_database.ebpfDatabase(args)
		ed.__main__()
		data = []

		while True:
			while queue.qsize() > 0:
				data.append(queue.get())
				if len(data) >= 100000: break

			if len(data) > 0:
				ed.__insert3__(data)
				data = []

################################################################################
	def __main__(self):
		self.__get_metadata__()
		self.__set_metadata__()
		self.__attach_function__()

		mproc = multiprocessing.Process(target = self.__metric_callback__, args = (self.args, self.ports, self.pair_key, ))
		mproc.start()

		proc = multiprocessing.Process(target = self.__update_callback__, args = (self.queue, self.args, ))
		proc.start()

		os.sched_setaffinity(os.getpid(), {6})
		os.sched_setaffinity(mproc.pid, {7})
		os.sched_setaffinity(proc.pid, {8})

		fp = open("procid", "w")
		fp.write(str(os.getpid()) + "\n")
		fp.write(str(mproc.pid) + "\n")
		fp.write(str(proc.pid) + "\n")
		fp.close()

		while True:
			try:
				self.b.ring_buffer_poll()
			except:
				logging.exception("message")
				return
