from bcc import BPF
import redis
import json
import ctypes
import logging
import multiprocessing
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
		self.b["event_ringbuf"].open_ring_buffer(self.__event_ringbuf_callback__)

		self.func_name = ["virtio_dev_tx_split", "virtio_dev_tx_packed", "virtio_dev_rx_split", "virtio_dev_rx_packed", "mlx5_rx_burst_vec", "mlx5_tx_burst_none_empw"]
		self.library_name = defaultdict()
		self.library_path = "/usr/local/lib/x86_64-linux-gnu/"
		self.attach_pos = defaultdict()

		self.metadata = None
		self.sampling_size = None

	def __get_metadata__(self):
		self.metadata = self.rd.get(self.rd_key).decode("utf-8")
		self.metadata = dict(json.loads(self.metadata))

		self.sampling_size = self.rd.get("sampling").decode("utf-8")
		self.sampling_size = dict(json.loads(self.sampling_size))

	def __set_metadata__(self):
		key = 1
		self.t_sampling_size[ctypes.c_uint8(key)] = ctypes.c_uint32(self.sampling_size["size"])

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
		self.attach_pos["mlx5_rx_burst_vec"] = "ret"
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
		self.ed.__insert1__(event_data)
		self.ed.__insert2__(event_data)
	
####################################################################################
	def __main__(self):
		self.__get_metadata__()
		self.__set_metadata__()
		self.__set_variable__()
		self.__attach_function__()

		while True:
			try:
				self.b.ring_buffer_consume()
			except:
				logging.exception("message")
				return
	
