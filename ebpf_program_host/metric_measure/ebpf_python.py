from bcc import BPF
import os
import redis
import json
import time
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

		self.func_name = ["virtio_dev_tx_split", "virtio_dev_tx_packed", "virtio_dev_rx_split", "virtio_dev_rx_packed", "mlx5_rx_burst_vec", "mlx5_tx_burst_none_empw"]
		self.library_name = defaultdict()
		self.library_path = "/usr/local/lib/x86_64-linux-gnu/"
		self.attach_pos = defaultdict()

		self.metadata = None
		self.sampling_size = None

		self.ports = multiprocessing.Queue()
		self.pair_key = multiprocessing.Queue()
		self.queue = multiprocessing.Queue()

	def __get_metadata__(self):
		self.metadata = self.rd.get(self.rd_key).decode("utf-8")
		self.metadata = dict(json.loads(self.metadata))

		self.sampling_size = self.rd.get("sampling").decode("utf-8")
		self.sampling_size = dict(json.loads(self.sampling_size))

	def __set_metadata__(self):
		key = 1
		self.t_sampling_size[ctypes.c_uint8(key)] = ctypes.c_uint32(self.sampling_size["size"])

		for port in range(6300, 6301):
			self.t_sampling_port[ctypes.c_uint16(port)] = ctypes.c_uint8(1)

	def __set_variable__(self):
		self.library_name["virtio_dev_tx_split"] = "librte_vhost.so"
		self.library_name["mlx5_tx_burst_none_empw"] = "librte_net_mlx5.so"
		self.library_name["virtio_dev_tx_packed"] = "librte_vhost.so"
		self.library_name["mlx5_rx_burst_vec"] = "librte_net_mlx5.so"
		self.library_name["virtio_dev_rx_split"] = "librte_vhost.so"
		self.library_name["virtio_dev_rx_packed"] = "librte_vhost.so"

		self.attach_pos["virtio_dev_tx_split"] = "ret"
		self.attach_pos["mlx5_tx_burst_none_empw"] = "entry"
		self.attach_pos["virtio_dev_tx_packed"] = "ret"
		self.attach_pos["mlx5_rx_burst_vec"] = "entry"
		self.attach_pos["virtio_dev_rx_split"] = "entry"
		self.attach_pos["virtio_dev_rx_packed"] = "entry"

####################################################################################
	def __attach_function__(self):
		for func_name in self.func_name:
			if self.attach_pos[func_name] == "entry":
				self.b.attach_uprobe(name = self.library_path + self.library_name[func_name], sym = func_name, fn_name = func_name)
			elif self.attach_pos[func_name] == "ret":
				self.b.attach_uretprobe(name = self.library_path + self.library_name[func_name], sym = func_name, fn_name = func_name)

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
				
####################################################################################
	def __main__(self):
		self.__get_metadata__()
		self.__set_metadata__()
		self.__set_variable__()
		self.__attach_function__()

		mproc = th.Thread(target = self.__metric_callback__, args = (self.args, self.port, self.pair_key, ))
		mproc.start()

		proc = multiprocessing.Process(target = self.__update_callback__, args = (self.queue, self.args, ))
		proc.start()

		os.sched_setaffinity(os.getpid(), {6})
		os.sched_setaffinity(mproc.pid, {7})
		os.sched_setaffinity(proc.pid, {8})

		while True:
			try:
				self.b.ring_buffer_poll()
			except:
				logging.exception("message")
				return
	
