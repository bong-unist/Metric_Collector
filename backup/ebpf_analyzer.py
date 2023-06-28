import redis
import json
import ctypes
import time
import threading as th
from collections import defaultdict
from queue import Queue

import ebpf_database

class ebpfAnalyzer:
	def __init__(self, ebpf_conf):
		self.ebpf_conf = ebpf_conf
		self.connect_info = self.ebpf_conf.connect_info
		self.redis_info = self.ebpf_conf.redis_info

		self.rd = redis.StrictRedis(host = self.redis_info["host"], port = self.redis_info["port"], db = 0)

		self.ed = ebpf_database.ebpfDatabase(self.ebpf_conf)
		self.ed.__connect__()
		self.ed.__delete__()
		self.ed.__create__()

		self.hh_ssize = None; self.hh_alpha = None
		self.hv_ssize = None; self.hv_alpha = None
		self.vv_ssize = None; self.vv_alpha = None
		self.ll_ssize = None; self.ll_alpha = None

		self.flow_id = set()
		self.calculation = set()
		self.vv_queue = Queue()
		self.vv_thread_cnt = 0

		self.host = []
		self.host_to_vm = defaultdict()
		self.hostname_to_metadata_key = defaultdict()
		self.metadata_key_to_hostname = defaultdict()
		self.time = defaultdict()

		self.vv_avg_diff_data_len = 0
		self.vv_cnt_diff_data_len = 0
	
###################################################################
	def __get_metadata1__(self):
		key1 = "servers"
		key2 = "sampling"

		for connect_info in self.connect_info[key1]:
			address = connect_info["address"]
			hostname = connect_info["hostname"]
			data = self.rd.get(address).decode("utf-8")
			self.time[hostname] = dict(json.loads(data))

		data = self.rd.get(key2).decode("utf-8")
		sampling_size = dict(json.loads(data))

		sampling_size["size"] = 10000000

		self.hh_ssize = sampling_size["size"]
		self.hh_alpha = 1500
#		self.hh_alpha = int(sampling_size["size"] * 0.001)

		self.hv_ssize = sampling_size["size"]
		self.hv_alpha = 5000
#		self.hv_alpha = int(sampling_size["size"] * 0.01)

		self.vv_ssize = sampling_size["size"]
		self.vv_alpha = 5000
#		self.vv_alpha = int(sampling_size["size"] * 0.01)

		self.ll_ssize = sampling_size["size"]
		self.ll_alpha = 5000
#		self.ll_alpha = int(sampling_size["size"] * 0.01)
	
	def __get_metadata2__(self):
		key = "servers"

		for connect_info in self.connect_info[key]:
			self.hostname_to_metadata_key[connect_info["hostname"]] = connect_info["metadata_key"]
			self.metadata_key_to_hostname[connect_info["metadata_key"]] = connect_info["hostname"]

		for connect_info in self.connect_info[key]:
			if connect_info.get("isvm") == None:
				self.host_to_vm[connect_info["metadata_key"]] = []
				self.host.append(connect_info["metadata_key"])

		for connect_info in self.connect_info[key]:
			if connect_info.get("isvm") != None:
				self.host_to_vm[connect_info["isvm"]].append(connect_info["metadata_key"])
	
	def __get_diff_ts__(self, node_id1, node_id2, ts1, ts2):
		hostname1 = self.metadata_key_to_hostname[node_id1]
		hostname2 = self.metadata_key_to_hostname[node_id2]

		server_ts1 = self.time[hostname1]["server_ts"]
		server_ts2 = self.time[hostname2]["server_ts"]

		ts1 = ts1 - server_ts1
		ts2 = ts2 - server_ts2

		manage_ts1 = self.time[hostname1]["management_ts"] + ts1
		manage_ts2 = self.time[hostname2]["management_ts"] + ts2

		latency = abs(manage_ts1 - manage_ts2)
		return latency
	
	def __get_time__(self, node_id, ts):
		hostname = self.metadata_key_to_hostname[node_id]
		server_ts = self.time[hostname]["server_ts"]
		ts = ts - server_ts
		manage_ts = self.time[hostname]["management_ts"] + ts
		return manage_ts

	def __preprocess__(self):
		self.__get_metadata1__()
		self.__get_metadata2__()

##############################################################################
	def __process1__(self, ed, fid, node_id, key, data_len, ssize):
		sql_data = ed.__query1__(fid, node_id, data_len[key], ssize)
		if not sql_data:
			ed.__reconnect__()
			sql_next_data = ed.__query1__(fid, node_id, data_len[key] + ssize, ssize)
			if not sql_next_data:
				ed.__reconnect__()
				return None
			data_len[key] += ssize
			return sql_next_data
		return sql_data

	def __process2__(self, ed, node_id, data, alpha):
		sql_data = ed.__query2__(node_id, data, alpha)
		if not sql_data:
			ed.__reconnect__()
			sql_next_data = ed.__query2__(node_id, data, alpha * 2)
			if not sql_next_data:
				ed.__reconnect__()
				return None
			return True
		return sql_data

	def __process4__(self, ed, node_id, data, alpha):
		sql_data = ed.__query4__(node_id, data, alpha)
		if not sql_data:
			ed.__reconnect__()
			sql_next_data = ed.__query4__(node_id, data, alpha * 2)
			if not sql_next_data:
				ed.__reconnect__()
				return None
			return True
		return sql_data

##############################################################################
	def __flow_id_analyzer__(self):
		ed = ebpf_database.ebpfDatabase(self.ebpf_conf)
		ed.__connect__()

		while True:
			datas = ed.__query0__()
			if not datas:
				time.sleep(1)
				ed.__reconnect__()
				continue
			for data in datas: self.flow_id.add(data["id"])
			ed.__reconnect__()
			time.sleep(1)

	def __hh_analyzer__(self, idx):
		sidx = (idx * 8)
		eidx = min(len(self.host), (idx + 1) * 8)

		prev_data_len = defaultdict()
		vm_prev_data_len = defaultdict()

		ed = ebpf_database.ebpfDatabase(self.ebpf_conf)
		ed.__connect__()

		while True:
			flow_id = list(self.flow_id)
			for fid in flow_id:
				for idx in range(sidx, eidx):
					host1 = self.host[idx]

					metadata_key = (host1, fid)
					if prev_data_len.get(metadata_key) == None: prev_data_len[metadata_key] = 0

					sql_data1 = self.__process1__(ed, fid, host1, metadata_key, prev_data_len, self.hh_ssize)
					if sql_data1 == None: continue

					for data1 in sql_data1:
						for host2 in self.host:
							if host1 == host2: continue
						
							sql_data2 = self.__process2__(ed, host2, data1, self.hh_alpha)
							if sql_data2 == None: continue
							if sql_data2 == True:
#								prev_data_len[metadata_key] += self.hh_ssize
								continue

							min_diff_data_len = ctypes.c_uint64(-1).value
							min_latency = None
							min_data = None
							manage_ts = None
							
							for data2 in sql_data2:
								metadata_key_ = (host2, fid)
								if prev_data_len.get(metadata_key_) == None: prev_data_len[metadata_key_] = 0
								if prev_data_len[metadata_key_] >= data2["data_len"]: continue

								diff_data_len = abs(data1["data_len"] - data2["data_len"])
								diff_ts = self.__get_diff_ts__(host1, host2, data1["ts"], data2["ts"])
								if min_diff_data_len > diff_data_len:
									min_diff_data_len = diff_data_len
									min_latency = diff_ts
									min_data = data2
									manage_ts = self.__get_time__(host1, data1["ts"])
							
							if min_data != None:
								ed.__query3__(host1, host2, data1, min_data, min_latency, manage_ts)
								self.vv_queue.put([host1, host2, vm_prev_data_len, fid, 0])
								ed.__reconnect__()

								metadata_key_ = (min_data["node_id"], min_data["flow_id"])
								prev_data_len[metadata_key_] = min_data["data_len"]

	def __hv_analyzer__(self, idx):
		sidx = (idx * 8)
		eidx = min(len(self.host), (idx + 1) * 8)

		prev_data_len = defaultdict()
		
		ed = ebpf_database.ebpfDatabase(self.ebpf_conf)
		ed.__connect__()

		avg_diff_data_len = 0
		cnt_diff_data_len = 0

		while True:
			flow_id = list(self.flow_id)
			for fid in flow_id:
				for idx in range(sidx, eidx):
					host = self.host[idx]
					
					metadata_key = (host, fid)
					if prev_data_len.get(metadata_key) == None: prev_data_len[metadata_key] = 0

					sql_data1 = self.__process1__(ed, fid, host, metadata_key, prev_data_len, self.hv_ssize)
					if sql_data1 == None: continue

					for data1 in sql_data1:
						print("hv cur", fid, host, data1["data_len"], prev_data_len[metadata_key])
						for vm in self.host_to_vm[host]:
							sql_data2 = self.__process2__(ed, vm, data1, self.hv_alpha)
							if sql_data2 == None: continue
							if sql_data2 == True:
								#prev_data_len[metadata_key] += self.hv_ssize
								continue

							min_diff_data_len = ctypes.c_uint64(-1).value
							min_latency = None
							min_data = None
							manage_ts = None

							for data2 in sql_data2:
								metadata_key_ = (vm, fid)
								if prev_data_len.get(metadata_key_) == None: prev_data_len[metadata_key_] = 0
								#if prev_data_len[metadata_key_] >= data2["data_len"]: continue

								diff_data_len = abs(data1["data_len"] - data2["data_len"])
								diff_ts = self.__get_diff_ts__(host, vm, data1["ts"], data2["ts"])

								if min_diff_data_len > diff_data_len:
									min_diff_data_len = diff_data_len
									min_latency = diff_ts
									min_data = data2
									manage_ts = self.__get_time__(host, data1["ts"])

							if min_data != None:
								ed.__query3__(host, vm, data1, min_data, min_latency, manage_ts)
								ed.__reconnect__()
								
#								avg_diff_data_len += min_diff_data_len
#								cnt_diff_data_len += 1
#								print("avg hv", int(avg_diff_data_len / cnt_diff_data_len))
#								print("update hv", data1["data_len"], min_data["data_len"], min_diff_data_len, min_latency)

								metadata_key_ = (min_data["node_id"], min_data["flow_id"])
								prev_data_len[metadata_key_] = min_data["data_len"]
					prev_data_len[metadata_key] += self.hv_ssize
	
	def __vv_analyzer1__(self):
		while True:
			if self.vv_queue.qsize() == 0:
				continue
			
			while self.vv_thread_cnt >= 10:
				time.sleep(0.01)

			data = self.vv_queue.get()
			if (data[0], data[1]) in self.calculation: 
				self.vv_queue.put(data)
				continue
			else: self.calculation.add((data[0], data[1]))

			th_ = th.Thread(target = self.__vv_analyzer2__, args = (data, ))
			th_.start()

			if data[4] <= 2:
				data[4] += 1
				self.vv_queue.put(data)

	def __vv_analyzer2__(self, arg):
		self.vv_thread_cnt += 1
		host1 = arg[0]
		host2 = arg[1]
		prev_data_len = arg[2]
		fid = arg[3]

		ed = ebpf_database.ebpfDatabase(self.ebpf_conf)
		ed.__connect__()

		for vm1 in self.host_to_vm[host1]:
			metadata_key = (vm1, fid)
			if prev_data_len.get(metadata_key) == None: prev_data_len[metadata_key] = 0

			sql_data1 = self.__process1__(ed, fid, vm1, metadata_key, prev_data_len, self.vv_ssize)
			if sql_data1 == None: continue

			for data1 in sql_data1:
				#print("vv cur", data1["data_len"])
				for vm2 in self.host_to_vm[host2]:
					sql_data2 = self.__process2__(ed, vm2, data1, self.vv_alpha)
					if sql_data2 == None: continue
					if sql_data2 == True:
#						prev_data_len[metadata_key] += self.vv_ssize
						continue

					min_diff_data_len = ctypes.c_uint64(-1).value
					min_latency = None
					min_data = None
					manage_ts = None

					for data2 in sql_data2:
						metadata_key_ = (vm2, fid)
						if prev_data_len.get(metadata_key_) == None: prev_data_len[metadata_key_] = 0
						#if prev_data_len[metadata_key_] >= data2["data_len"]: continue

						diff_data_len = abs(data1["data_len"] - data2["data_len"])
						diff_ts = self.__get_diff_ts__(vm1, vm2, data1["ts"], data2["ts"])

						if min_diff_data_len > diff_data_len:
							min_diff_data_len = diff_data_len
							min_latency = diff_ts
							min_data = data2
							manage_ts = self.__get_time__(vm1, data1["ts"])

					if min_data != None:
						ed.__query3__(vm1, vm2, data1, min_data, min_latency, manage_ts)
						ed.__reconnect__()
						
#						self.vv_avg_diff_data_len += min_diff_data_len
#						self.vv_cnt_diff_data_len += 1
#						print("vv avg", int(self.vv_avg_diff_data_len / self.vv_cnt_diff_data_len))
#						print("update vv", data1["data_len"], min_data["data_len"], min_diff_data_len, min_latency)
						
						metadata_key_ = (min_data["node_id"], fid)
						prev_data_len[metadata_key_] = min_data["data_len"]

			prev_data_len[metadata_key] += self.vv_ssize
		
		self.vv_thread_cnt -= 1
		self.calculation.discard((host1, host2))

	def __ll_analyzer__(self):
		prev_data_len = defaultdict()
		vms = []

		ed = ebpf_database.ebpfDatabase(self.ebpf_conf)
		ed.__connect__()

		avg_diff_data_len = 0
		cnt_diff_data_len = 0

		for host in self.host:
			for vm in self.host_to_vm[host]: vms.append(vm)

		while True:
			flow_id = list(self.flow_id)
			for fid in flow_id:
				for i in range(2):
					servers = None
					if i == 0: servers = self.host
					else: servers = vms

					for server in servers:
						metadata_key = (server, fid)
						if prev_data_len.get(metadata_key) == None: prev_data_len[metadata_key] = 0

						sql_data1 = self.__process1__(ed, fid, server, metadata_key, prev_data_len, self.ll_ssize)
						if sql_data1 == None: continue

						for data1 in sql_data1:
							sql_data2 = self.__process4__(ed, server, data1, self.ll_alpha)
							if sql_data2 == None: continue
							if sql_data2 == True:
#								prev_data_len[metadata_key] += self.ll_ssize
								continue

							min_diff_data_len = ctypes.c_uint64(-1).value
							min_latency = None
							min_data = None
							manage_ts = None

							for data2 in sql_data2:
								diff_data_len = abs(data1["data_len"] - data2["data_len"])
								diff_ts = self.__get_diff_ts__(server, server, data1["ts"], data2["ts"])
								if min_diff_data_len > diff_data_len and diff_data_len <= 5000:
									min_diff_data_len = diff_data_len
									min_latency = diff_ts
									min_data = data2
									manage_ts = self.__get_time__(server, data1["ts"])

							if min_data != None:
								ed.__query3__(server, server, data1, min_data, min_latency, manage_ts)
								ed.__reconnect__()

#								avg_diff_data_len += min_diff_data_len
#								cnt_diff_data_len += 1
#								print(fid, data1["data_len"], min_data["data_len"])
#								print("avg ll", int(avg_diff_data_len / cnt_diff_data_len), min_diff_data_len, min_latency)

						prev_data_len[metadata_key] += self.ll_ssize
##################################################################################
	def __mainprocess__(self):
		print("analyzer start")
		cnt = (len(self.host) // 8) + 1

		th_ = th.Thread(target = self.__flow_id_analyzer__, args = ())
		th_.start()

		for i in range(0, cnt):
			th_ = th.Thread(target = self.__hh_analyzer__, args = (i, ))
			th_.start()

			th_ = th.Thread(target = self.__hv_analyzer__, args = (i, ))
			th_.start()

		th_ = th.Thread(target = self.__vv_analyzer1__, args = ())
		th_.start()

		th_ = th.Thread(target = self.__ll_analyzer__, args = ())
		th_.start()

		th_.join()

##################################################################################
	def __main__(self):
		print("start iperf")
		print("Push Any Button to Start Analyzer")
		input()
		self.__preprocess__()
		self.__mainprocess__()

							
















