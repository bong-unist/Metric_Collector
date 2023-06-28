from bcc import BPF
import pyroute2
import socket
import redis
import multiprocessing
import ctypes
import time
import logging
import csv
import json
import getmac
from collections import defaultdict

import threading as th

from time_sync_manage import ebpf_code

class ebpfPython:
	def __init__(self, ebpf_conf):
		self.ebpf_conf = ebpf_conf
		self.management_server_info = self.ebpf_conf.management_server_info
		self.connect_info = self.ebpf_conf.connect_info

		self.rd = redis.StrictRedis(host = "localhost", port = 6379, db = 0)
		self.exdp = ebpf_code.ebpfCode()
		self.code = self.exdp.__main__()
		self.b = BPF(text = self.code, cflags = ["-w", "-std=gnu99", "-DNUM_CPUS=%d" % multiprocessing.cpu_count()])

		self.devmap = self.b.get_table("tx_port")
		self.port_to_addr = self.b.get_table("port_to_addr")
		self.port_to_macaddr = self.b.get_table("port_to_macaddr")

		self.addr = defaultdict()
		self.macaddr = defaultdict()

		self.ping_port = 5999
		self.eth = self.management_server_info["eth"][0]

		self.min_rtt = defaultdict()

######################################################################
	def __change_addr_to_str__(self, addr):
		addr_str = str(bin(int(addr)))[2:]
		addr_str = addr_str.zfill(32)
		addr_str = addr_str[::-1]

		addr = []
		num = 1; ssum = 0
		for ch in addr_str:
			if ch == '1': ssum += num
			num = num * 2
			if num >= pow(2, 8):
				addr.append(ssum)
				num = 1; ssum = 0
		addr.append(ssum)

		addr = (str(addr[3]) + "." + str(addr[2]) + "." + str(addr[1]) + "." + str(addr[0]))
		return addr

######################################################################
	def __set_addr_port__(self):
		key1 = "servers"
		key2 = "address"
		key3 = "port"
		
		for idx, connect_info in enumerate(self.connect_info[key1]):
			if connect_info.get("iscontainer") != None: continue
			address = connect_info[key2]
			fake_port = idx + 1
			self.addr[address] = fake_port
		self.addr[self.management_server_info[key2]] = self.ping_port

	def __set_devmap__(self, eth):
		ip = pyroute2.IPRoute()
		idx = ip.link_lookup(ifname = eth)[0]
		self.devmap[ctypes.c_uint32(0)] = ctypes.c_int(idx)

	def __get_macaddr__(self):
		with open("/proc/net/arp") as arp_table:
			try:
				reader = csv.reader(arp_table, skipinitialspace = True, delimiter = ' ')
				reader = list(reader)
				macaddrs = {data[0] : data[3] for data in reader[1:]}

				for key, value in macaddrs.items():
					self.macaddr[key] = value.replace(":", "")
				self.macaddr[self.management_server_info["address"]] = getmac.get_mac_address().replace(":", "")
			except:
				logging.exception("message")
				return False
			return True
	
	def __set_macaddr__(self):
		for addr, macaddr in self.macaddr.items():
			if self.addr.get(addr) == None : continue
			macaddr_bin = "0b"
			for digit in macaddr:
				bin_ = bin(int(digit, 16))
				bin_ = bin_[2:]
				bin_ = bin_.zfill(4)
				macaddr_bin += bin_
			macaddr_int = int(macaddr_bin, 2)
			self.port_to_macaddr[ctypes.c_uint16(self.addr[addr])] = ctypes.c_uint64(macaddr_int)

	def __set_addr__(self):
		for addr, fake_port in self.addr.items():
			addr = addr.split(".")
			addr_bin = ""
			for digit in addr:
				addr_temp = bin(int(digit))[2:]
				addr_temp = addr_temp.zfill(8)
				addr_bin += addr_temp

			addr_bin = addr_bin[24:32] + addr_bin[16:24] + addr_bin[8:16] + addr_bin[0:8]
			addr_bin = "0b" + addr_bin
			addr_int = int(addr_bin, 2)

			self.port_to_addr[ctypes.c_uint16(fake_port)] = ctypes.c_uint32(addr_int)
	
	def __set_redis__(self, data, rtt, dst_addr):
		json_data = defaultdict()
		json_data["management_ts"] = int(data.send_ts)
		json_data["server_ts"] = (int(data.server_ts) - rtt)
		json_data = json.dumps(json_data, ensure_ascii = False).encode("utf-8")
		
		self.rd.set(dst_addr, json_data)
		
######################################################################
	def __xdp_event__(self, cpu, data, size):
		data = self.b["xdp_events"].event(data)
		src_addr = self.__change_addr_to_str__(data.src_addr)
		dst_addr = self.__change_addr_to_str__(data.dst_addr)

		rtt = (int(data.recv_ts) - int(data.send_ts)) // 2

		if self.min_rtt.get(dst_addr) == None : 
			print("recv from ", dst_addr, rtt)
			self.min_rtt[dst_addr] = rtt
			self.__set_redis__(data, rtt, dst_addr)
		elif self.min_rtt[dst_addr] > rtt: 
			print("update ", dst_addr, rtt)
			self.__set_redis__(data, rtt, dst_addr)	
			self.min_rtt[dst_addr] = rtt

	def __send_ping__(self):
		message = "ping pong"
		print(message)
		
		for addr, fake_port in self.addr.items():
			if fake_port == self.ping_port: continue
			client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			client_socket.sendto(message.encode(), ("127.0.0.1", fake_port))
			client_socket.close()
			
#######################################################################
	def __attach_function__(self):
		in_fn = self.b.load_func("syncTimeProtocol", BPF.XDP)
		eths = self.management_server_info["eth"]

		for eth in eths:
			self.b.attach_xdp(eth, in_fn, 0)
			if eth != "lo": self.__set_devmap__(eth)

		self.b["xdp_events"].open_perf_buffer(self.__xdp_event__)
	
	def __detach_function__(self):
		eths = self.management_server_info["eth"]

		for eth in eths:
			self.b.remove_xdp(eth, 0)

	def __poll_ebpf_event__(self):
		try_cnt = 0

		while try_cnt < 30:
			try:
				self.__send_ping__()
				self.b.perf_buffer_poll(timeout = 1)
#				self.b.trace_print()
				try_cnt = try_cnt + 1
			except:
				logging.exception("message")
			time.sleep(1)

	def __tmp_thread__(self):
		while True:
			self.__send_ping__()
			time.sleep(1)

############################################################################
	def __main__(self):
		self.__set_addr_port__()
		self.__set_addr__()
		self.__get_macaddr__()
		self.__set_macaddr__()

		self.__attach_function__()
#		th_ = th.Thread(target = self.__tmp_thread__, args = ())
#		th_.start()
		self.__poll_ebpf_event__()
		self.__detach_function__()


	



















