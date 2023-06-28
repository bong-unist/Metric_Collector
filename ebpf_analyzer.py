import redis
import os
import json
import time
import threading as th
from collections import defaultdict
from queue import Queue
from multiprocessing import shared_memory
import multiprocessing as mp
import numpy as np

import ebpf_database

import logging

class ebpfAnalyzer:
	def __init__(self, ebpf_conf, analyzer_type, fid):
		self.ebpf_conf = ebpf_conf
		self.analyzer_type = analyzer_type
		self.shm_name = None

		self.connect_info = self.ebpf_conf.connect_info
		self.database_info = self.ebpf_conf.database_info
		self.redis_info = self.ebpf_conf.redis_info

		self.rd = redis.StrictRedis(host = self.redis_info["host"], port = self.redis_info["port"], db = 0)

		self.time = defaultdict()
		self.flow_id = set()
		self.flow_id_info = defaultdict()
		self.flow_id_cache = defaultdict()
		self.server_info_cache = defaultdict()
		self.ssize = None
		self.alpha = None

		self.host = []
		self.host_to_vm = defaultdict()
		self.vm_to_host = defaultdict()
		self.metadata_key_to_hostname = defaultdict()
		self.addr_to_metadata_key = defaultdict()
		self.servers = None

		self.server_info = defaultdict()
		self.hyper_info = defaultdict()

		self.throughput = defaultdict()
		self.loss_rate = defaultdict()

		self.store_queue = mp.Queue()
		self.statistical_data_queue = mp.Queue()
		self.server_info_queue = mp.Queue()

		self.overlap = set()

#		self.flow_id.add(fid)

		if self.analyzer_type == 0:
			self.shm = shared_memory.SharedMemory(create = True, size = 16000)
			shm_name = self.shm.name
			shm_name = shm_name.encode("utf-8")
			self.rd.set("shm_name", shm_name)
		else:
			self.shm_name = self.rd.get("shm_name").decode("utf-8")
			self.shm = shared_memory.SharedMemory(name = self.shm_name)

		self.__main__()

##############################################################
	def __get_metadata1__(self):
		for connect_info in self.connect_info["servers"]:
			if connect_info.get("iscontainer") != None: continue
			if connect_info.get("address") == None: continue
			address = connect_info["address"]
			data = self.rd.get(address).decode("utf-8")
			self.time[address] = dict(json.loads(data))

		data = self.rd.get("sampling").decode("utf-8")
		sampling_size = dict(json.loads(data))
		sampling_size["size"] = 10000000

		self.ssize = sampling_size["size"]
		self.alpha = 1000
	
	def __get_diff_ts__(self, node_id1, node_id2, ts1, ts2):
		hostname1 = self.metadata_key_to_hostname[node_id1]
		hostname2 = self.metadata_key_to_hostname[node_id2]

		try:
			server_ts1 = self.time[hostname1]["server_ts"]
			server_ts2 = self.time[hostname2]["server_ts"]
		except:
			return None

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
	
	def __get_data__(self, ed, fid, server, metadata_key, prev_data_len, evt_type = None):
		sql_data = None
		if self.analyzer_type != 3:
			sql_data = self.__process1__(ed, fid, server, metadata_key, prev_data_len, self.ssize, evt_type)
		else:
			if evt_type == None:
				sql_data = self.__process2__(ed, fid, server)
			else:
				sql_data = self.__process3__(ed, fid, server, metadata_key, prev_data_len, self.ssize, evt_type)
		return sql_data

	def __preprocess__(self):
		self.__get_metadata1__()

#################################################################
	def __process1__(self, ed, fid, node_id, key, data_len, ssize, evt_type):
		sql_data = ed.__query1__(fid, node_id, data_len[key], ssize, evt_type)
		if not sql_data:
			ed.__reconnect__()
			sql_next_data = ed.__query1__(fid, node_id, data_len[key] + ssize, ssize, evt_type)
			if not sql_next_data:
				ed.__reconnect__()
				return None
			data_len[key] += ssize
			return sql_next_data
		return sql_data

	def __process2__(self, ed, fid, node_id):
		sql_data = ed.__query2__(fid, node_id)
		return sql_data
	
	def __process3__(self, ed, fid, node_id, key, data_len, ssize, evt_type):
		sql_data = ed.__query3__(fid, node_id, data_len[key], ssize, evt_type)
		if not sql_data:
			ed.__reconnect__()
			sql_next_data = ed.__query3__(fid, node_id, data_len[key] + ssize, ssize, evt_type)
			if not sql_next_data:
				ed.__reconnect__()
				return None
			data_len[key] += ssize
			return sql_next_data
		return sql_data

##################################################################
	def __statistical_data__(self, key, data):
		if self.throughput.get(key) == None: self.throughput[key] = [data["ts"], data["data_len"]] # ts, bytes
		if self.loss_rate.get(key) == None: self.loss_rate[key] = [data["ts"], 0, 0] # ts, loss, total
		
		if data["is_retrans"] == 0: self.loss_rate[key][2] += 1
		if data["is_retrans"] == 1: self.loss_rate[key][1] += 1

		diff_ts = data["ts"] - self.throughput[key][0]
		
		if diff_ts >= 1000000000: 
			flow_id = data["flow_id"]
			node_id = data["node_id"]
			evt_type = data["evt_type"]
			manage_ts = self.__get_time__(node_id, data["ts"])

			throughput = round((float(data["data_len"] - self.throughput[key][1]) / 1000000), 2)
			loss_rate = round(float((self.loss_rate[key][1] / self.loss_rate[key][2])) * 100, 2)

			self.throughput[key] = [data["ts"], data["data_len"]]
			self.loss_rate[key] = [data["ts"], 0, 0]		

			self.statistical_data_queue.put([flow_id, node_id, manage_ts, throughput, loss_rate, evt_type])
		
	def __store_process__(self, fid, server1, server2, sql_data1, sql_data2, ishost = True):
		diff_ts = self.__get_diff_ts__(server1, server2, sql_data1["ts"], sql_data2["ts"])
		if diff_ts == None: return False
		manage_ts1 = self.__get_time__(server1, sql_data1["ts"])
		manage_ts2 = self.__get_time__(server2, sql_data2["ts"])

#		if diff_ts >= 1000000000: return True
#		if sql_data1["data_len"] != sql_data2["data_len"]: return False
#		if abs(sql_data1["data_len"] - sql_data2["data_len"]) >= self.alpha: return False

		if server1 > server2:
			server1, server2 = server2, server1
			sql_data1, sql_data2 = sql_data2, sql_data1

		if server1 <= server2:
			self.store_queue.put([server1, server2, sql_data1, sql_data2, diff_ts, manage_ts1, manage_ts2])
		else:
			self.store_queue.put([server2, server1, sql_data2, sql_data1, diff_ts, manage_ts2, manage_ts1])
		return True

##################################################################
	def __flow_id_analyzer__(self):
		ed = ebpf_database.ebpfDatabase(self.ebpf_conf)
		ed.__connect__()

		while True:
			datas = ed.__query0__()
			arr_datas = []
			if not datas:
				ed.__reconnect__()
				continue
			for data in datas: arr_datas.append(data["id"])
			np_datas = np.array(arr_datas)
			ndp_datas = np.ndarray(np_datas.shape, dtype = np_datas.dtype, buffer = self.shm.buf)
			ndp_datas[:] = np_datas[:]
			time.sleep(1)
			
	def __flow_analyzer__(self):
		while True:
			datas = np.ndarray((-1, ), dtype = np.int64, buffer = self.shm.buf)
			np.trim_zeros(datas, trim = "fb")
			for data in datas: 
				if data == 0: continue
				self.flow_id.add(data)

			while self.server_info_queue.qsize() > 0:
				data = self.server_info_queue.get()
				self.server_info_cache[data["addr"]] = data

			time.sleep(1)


	def __hh_analyzer__(self, idx):
		sidx = (idx * 8)

		prev_data_len = defaultdict()

		ed = ebpf_database.ebpfDatabase(self.ebpf_conf)
		ed.__connect__()
		
		while True:
			flow_id = list(self.flow_id)
			eidx = min(len(list(self.flow_id)), (idx + 1) * 8)
			for fidx in range(sidx, eidx):
				try: fid = flow_id[fidx]
				except: break
				if self.flow_id_cache.get(fid) == None:
					self.flow_id_cache[fid] = ed.__get_flow_info__(fid)[0]

				try:
					src_addr = self.flow_id_cache[fid]["src_addr"]
					dst_addr = self.flow_id_cache[fid]["dst_addr"]

					server1 = self.server_info[src_addr]
					server2 = self.server_info[dst_addr]
					server1 = server1 if self.hyper_info.get(src_addr) == None else self.hyper_info[src_addr]
					server2 = server2 if self.hyper_info.get(dst_addr) == None else self.hyper_info[dst_addr]
				except:
					continue

				evt_type1 = 3
				evt_type2 = 7

				metadata_key = (server1, fid)
				if prev_data_len.get(metadata_key) == None: prev_data_len[metadata_key] = 0

				sql_data1 = self.__get_data__(ed, fid, server1, metadata_key, prev_data_len, evt_type1)
				if not sql_data1: continue

				sql_data2 = self.__get_data__(ed, fid, server2, metadata_key, prev_data_len, evt_type2)
				if not sql_data2: continue
				
				len1 = len(sql_data1)
				len2 = len(sql_data2)
				idx1 = 0
				idx2 = 0

				while idx1 < len1 and idx2 < len2:
					while idx2 < len2 and sql_data1[idx1]["data_len"] > sql_data2[idx2]["data_len"]: idx2 += 1
					if idx2 < len2:
						self.__store_process__(fid, server1, server2, sql_data1[idx1], sql_data2[idx2])
						metadata_key_ = (sql_data2[idx2]["node_id"], fid)
						prev_data_len[metadata_key_] = sql_data2[idx2]["data_len"]
					else: break

					while idx1 < len1 and sql_data1[idx1]["data_len"] <= sql_data2[idx2]["data_len"]: idx1 += 1

					if idx1 < len1:
						prev_data_len[metadata_key] = sql_data1[idx1]["data_len"]
	
	def __hv_analyzer__(self, idx):
		sidx = (idx * 8)

		prev_data_len = defaultdict()

		ed = ebpf_database.ebpfDatabase(self.ebpf_conf)
		ed.__connect__()

		while True:
			flow_id = list(self.flow_id)
			eidx = min(len(list(self.flow_id)), (idx + 1) * 8)
			for fidx in range(sidx, eidx):
				try: fid = flow_id[fidx]
				except: break
				if self.flow_id_cache.get(fid) == None:
					self.flow_id_cache[fid] = ed.__get_flow_info__(fid)[0]

				try:
					src_addr = self.flow_id_cache[fid]["src_addr"]
					dst_addr = self.flow_id_cache[fid]["dst_addr"]

					server1_vm = self.server_info[src_addr]
					server1 = None if self.hyper_info.get(src_addr) == None else self.hyper_info[src_addr]
					server1_vm_evt_type = 3
					server1_evt_type = 7

					server2_vm = self.server_info[dst_addr]
					server2 = None if self.hyper_info.get(dst_addr) == None else self.hyper_info[dst_addr]
					server2_vm_evt_type = 7
					server2_evt_type = 3
				except: 
					continue

				server_list = []
				server_list.append([server1_vm, server1, server1_vm_evt_type, server1_evt_type])
				server_list.append([server2_vm, server2, server2_vm_evt_type, server2_evt_type])

				for server in server_list:
					server_vm = server[0]
					server_host = server[1]
					server_vm_evt_type = server[2]
					server_host_evt_type = server[3]

					if server_host == None: continue

					metadata_key = (server_host, fid)
					if prev_data_len.get(metadata_key) == None: prev_data_len[metadata_key] = 0

					sql_data1 = self.__get_data__(ed, fid, server_host, metadata_key, prev_data_len, server_host_evt_type)
					if not sql_data1: continue

					sql_data2 = self.__get_data__(ed, fid, server_vm, metadata_key, prev_data_len, server_vm_evt_type)
					if not sql_data2: continue

					len1 = len(sql_data1)
					len2 = len(sql_data2)
					idx1 = 0
					idx2 = 0

					while idx1 < len1 and idx2 < len2:
						while idx2 < len2 and sql_data1[idx1]["data_len"] > sql_data2[idx2]["data_len"]: idx2 += 1
						if idx2 < len2:
							self.__store_process__(fid, server_host, server_vm, sql_data1[idx1], sql_data2[idx2])
							metadata_key_ = (sql_data2[idx2]["node_id"], fid)
							prev_data_len[metadata_key_] = sql_data2[idx2]["data_len"]
						else: break

						while idx1 < len1 and sql_data1[idx1]["data_len"] <= sql_data2[idx2]["data_len"]: idx1 += 1
						
						if idx1 < len1:
							prev_data_len[metadata_key] = sql_data1[idx1]["data_len"]
	
	def __vv_analyzer__(self, idx):
		sidx = (idx * 8)

		ed = ebpf_database.ebpfDatabase(self.ebpf_conf)
		ed.__connect__()

		prev_data_len = defaultdict()
		
		while True:
			flow_id = list(self.flow_id)
			eidx = min(len(list(self.flow_id)), (idx + 1) * 8)
			for fidx in range(sidx, eidx):
				try: fid = flow_id[fidx]
				except: break
				if self.flow_id_cache.get(fid) == None:
					self.flow_id_cache[fid] = ed.__get_flow_info__(fid)[0]

				try:
					src_addr = self.flow_id_cache[fid]["src_addr"]
					dst_addr = self.flow_id_cache[fid]["dst_addr"]

					server1 = self.server_info[src_addr]
					server2 = self.server_info[dst_addr]
				except: 
					continue

				evt_type1 = 0
				evt_type2 = 4
			
				metadata_key = (server1, fid)
				if prev_data_len.get(metadata_key) == None: prev_data_len[metadata_key] = 0

				sql_data1 = self.__get_data__(ed, fid, server1, metadata_key, prev_data_len, evt_type1)
				if sql_data1 == None: continue

				sql_data2 = self.__get_data__(ed, fid, server2, metadata_key, prev_data_len, evt_type2)
				if sql_data2 == None: continue

				len1 = len(sql_data1)
				len2 = len(sql_data2)
				idx1 = 0
				idx2 = 0

				while idx1 < len1 and idx2 < len2:
					while idx2 < len2 and sql_data1[idx1]["data_len"] > sql_data2[idx2]["data_len"]: idx2 += 1
					if idx2 < len2:
						self.__store_process__(fid, server1, server2, sql_data1[idx1], sql_data2[idx2])
						metadata_key_ = (sql_data2[idx2]["node_id"], fid)
						prev_data_len[metadata_key_] = sql_data2[idx2]["data_len"]
					else: break

					while idx1 < len1 and sql_data1[idx1]["data_len"] <= sql_data2[idx2]["data_len"]: idx1 += 1

					if idx1 < len1:
						prev_data_len[metadata_key] = sql_data1[idx1]["data_len"]

	def __ll_analyzer__(self, idx):
		sidx = idx * 8

		prev_data_len = defaultdict()
		cache_evt_type = defaultdict()

		ed = ebpf_database.ebpfDatabase(self.ebpf_conf)
		ed.__connect__()

		while True:
			flow_id = list(self.flow_id)
			eidx = min(len(flow_id), (idx + 1) * 8)
			for fidx in range(sidx, eidx):
				try: fid = flow_id[fidx]
				except: break
				if self.flow_id_cache.get(fid) == None:
					self.flow_id_cache[fid] = ed.__get_flow_info__(fid)[0]
				
				for i in range(2):
					try:
						addr = self.flow_id_cache[fid]["src_addr"] if i == 0 else self.flow_id_cache[fid]["dst_addr"]
						server = self.server_info[addr]
					except: 
						continue

					metadata_key = (server, fid)
					if prev_data_len.get(metadata_key) == None:
						prev_data_len[metadata_key] = 0
					if cache_evt_type.get(metadata_key) == None:
						cache_evt_type[metadata_key] = self.__get_data__(ed, fid, server, metadata_key, prev_data_len)

					evt1 = 0; evt2 = 1

					update = False

					while evt2 < len(cache_evt_type[metadata_key]):
						sql_data1 = self.__get_data__(ed, fid, server, metadata_key, prev_data_len, cache_evt_type[metadata_key][evt1]["evt_type"])
						sql_data2 = self.__get_data__(ed, fid, server, metadata_key, prev_data_len, cache_evt_type[metadata_key][evt2]["evt_type"])

						if not sql_data1 or not sql_data2:
							evt1 += 1; evt2 += 1
							continue

						if cache_evt_type[metadata_key][evt1]["evt_type"] == 3 and cache_evt_type[metadata_key][evt2]["evt_type"] == 4:
							sql_data2 = self.__get_data__(ed, fid, server, metadata_key, prev_data_len, 7)
							if not sql_data2: 
								evt1 += 1; evt2 += 1
								continue

						len1 = len(sql_data1)
						len2 = len(sql_data2)
						idx1 = 0
						idx2 = 0

						metric_key1 = (server, fid, sql_data1[0]["evt_type"])
						metric_key2 = (server, fid, sql_data2[0]["evt_type"])

						update = True
						while idx1 < len1 and idx2 < len2:
							while idx2 < len2 and sql_data1[idx1]["data_len"] > sql_data2[idx2]["data_len"]: 
								self.__statistical_data__(metric_key2, sql_data2[idx2])
								idx2 += 1
							if idx2 < len2:
								self.__store_process__(fid, server, server, sql_data1[idx1], sql_data2[idx2])
							else: break

							while idx1 < len1 and sql_data1[idx1]["data_len"] <= sql_data2[idx2]["data_len"]: 
								self.__statistical_data__(metric_key1, sql_data1[idx1])
								idx1 += 1

						evt1 += 1; evt2 += 1

					if update:
						prev_data_len[metadata_key] += self.ssize

	def __store_analyzer__(self, store_queue):
		ed = ebpf_database.ebpfDatabase(self.ebpf_conf)
		ed.__connect__()

		while True:
			while store_queue.qsize() > 0:
				data = store_queue.get()
				ed.__query4__(0, data[0], data[1], data[2], data[3], data[4], data[5], data[6])
			ed.__query5__(0)

	def __store_statistical_data__(self, statistical_data_queue):
		ed = ebpf_database.ebpfDatabase(self.ebpf_conf)
		ed.__connect__()

		while True:
			while statistical_data_queue.qsize() > 0:
				data = statistical_data_queue.get()
				ed.__query6__(data)
			ed.__query7__()

	def __get_server_info__(self):
		ed = ebpf_database.ebpfDatabase(self.ebpf_conf)
		ed.__connect__()

		while True:
			datas = ed.__get_server_info__()
			for data in datas:
				# host 일때 (is_vm, is_container, is_other == -1)
				# vm 일때 (is_vm != -1)
				# container 일때 (is_container != -1)
				# 다른 주소를 가지고 있을 때 (is_other != -1)
				if data["is_vm"] != -1:
					self.server_info[data["addr"]] = data["node_id"]
					self.hyper_info[data["addr"]] = data["is_vm"]
					self.metadata_key_to_hostname[data["node_id"]] = data["addr"]
				elif data["is_container"] != -1:
					self.server_info[data["addr"]] = data["is_container"]
				elif data["is_other"] != -1:
					self.server_info[data["addr"]] = data["is_other"]
				else:
					self.server_info[data["addr"]] = data["node_id"]
					self.metadata_key_to_hostname[data["node_id"]] = data["addr"]
			time.sleep(1)

####################################################################
	def __mainprocess__(self):
		print("analyzer start")
		if self.analyzer_type == 0:
			th_ = th.Thread(target = self.__flow_id_analyzer__, args = ())
			th_.start()
			th_.join()
		else:
			cnt = int(self.rd.get("analyzer_id"))

			th_ = th.Thread(target = self.__flow_analyzer__, args = ())
			th_.start()

			proc = mp.Process(target = self.__store_analyzer__, args = (self.store_queue, ))
			proc.start()

			proc_ = mp.Process(target = self.__store_statistical_data__, args = (self.statistical_data_queue, ))
			proc_.start()

			proc__ = th.Thread(target = self.__get_server_info__, args = ())
			proc__.start()

			for i in range(cnt):
				if self.analyzer_type == 1:
					th_ = th.Thread(target = self.__hh_analyzer__, args = (i, ))
					th_.start()
				elif self.analyzer_type == 2:
					th_ = th.Thread(target = self.__hv_analyzer__, args = (i, ))
					th_.start()
				elif self.analyzer_type == 3:
					th_ = th.Thread(target = self.__ll_analyzer__, args = (i, ))
					th_.start()
				elif self.analyzer_type == 4:
					th_ = th.Thread(target = self.__vv_analyzer__, args = (i, ))
					th_.start()

			t1 = self.analyzer_type - 1
			t2 = os.cpu_count()
			os.sched_setaffinity(os.getpid(), {(t1 * 2) % os.cpu_count()})
			os.sched_setaffinity(proc.pid, {(t2 * 2 + 1) % os.cpu_count()})

			th_.join()

####################################################################
	def __main__(self):
		self.__preprocess__()
		self.__mainprocess__()














		
