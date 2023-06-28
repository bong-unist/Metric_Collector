import ctypes
import json
import time
import psutil
import redis
import pymysql
#import matplotlib
#import matplotlib.pyplot as plt
from collections import defaultdict
from datetime import datetime

import ebpf_database

class ebpfGraph:
	def __init__(self):
		self.database_info = defaultdict()
		self.database_info["user"] = "bw"
		self.database_info["passwd"] = "qhd7812"
		self.database_info["host"] = "10.1.1.201"
		self.database_info["db"] = "metric"

		self.redis_info = defaultdict()
		self.redis_info["host"] = "10.1.1.201"
		self.redis_info["port"] = 6379

		self.rd = redis.StrictRedis(host = self.redis_info["host"], port = self.redis_info["port"], db = 0)

		self.connect_info = defaultdict()
		self.connect_info[1] = "10.1.1.1"
		self.connect_info[2] = "10.1.1.2"
		self.connect_info[3] = "10.1.1.26"
		self.connect_info[4] = "10.1.1.27"

		self.layer_info = defaultdict()
		self.layer_info[0] = "sock"
		self.layer_info[1] = "tcp"
		self.layer_info[2] = "ip"
		self.layer_info[3] = "sock"
		self.layer_info[4] = "tcp"
		self.layer_info[5] = "ip"

		self.db = None
		self.cursor = None

		self.flow_id = defaultdict()
		self.data_len = 0
		self.plus_data_len = 100000

		self.time = defaultdict()
		self.min_time = ctypes.c_uint64(-1).value
		self.min_time_ = ctypes.c_uint64(-1).value
		
		self.data = defaultdict()
		self.local_data = defaultdict()
		self.metric_data = defaultdict()

		self.cur_time_ns = time.time_ns()
		self.boot_time_ns = None
		with open("/proc/uptime", "r") as f:
			data = f.readline()
			self.boot_time_ns = int(float(data.split()[0])) * 1000000000 + int(float(data.split()[1]))
	
	def __connect__(self):
		self.db = pymysql.connect(
			user = self.database_info["user"],
			passwd = self.database_info["passwd"],
			host = self.database_info["host"],
			db = self.database_info["db"],
			charset = "utf8"
		)
		self.cursor = self.db.cursor(pymysql.cursors.DictCursor)
	
	def __preprocess__(self):
		datas = self.__query0__()
		if not datas: return None
		
		for data in datas:
			self.flow_id[data["id"]] = [data["src_addr"], data["dst_addr"], data["src_port"], data["dst_port"]]

		key = "servers"
		
		for key in range(1, 5):
			data = self.rd.get(self.connect_info[key]).decode("utf-8")
			self.time[key] = dict(json.loads(data))

		datas = self.__query1__()
		for data in datas:
			self.__get_time2__(data, 1)

		datas = self.__query2__()
		for data in datas:
			self.__get_time2__(data, 0)

	def __get_time0__(self, node_id, ts):
		server_ts = self.time[node_id]["server_ts"]
		ts = ts - server_ts
		ts = ts + self.time[node_id]["management_ts"]
		return ts

#		ts = self.boot_time_ns - ts
#		cur_time = self.cur_time_ns - ts
#		cur_time = float(cur_time / 1000000000)
#		
#		date = datetime.fromtimestamp(cur_time).strftime("%Y-%m-%d %H:%M:%S.%f")
#		nano_sec = date.split(" ")[1]
#		nano_sec = nano_sec.split(".")[1]
#
#		cur_time += int(nano_sec) / 1000
#		return datetime.fromtimestamp(cur_time).strftime("%Y-%m-%d %H:%M:%S")
#		return cur_time
	
	def __get_time1__(self, manage_ts):
		return manage_ts
#		ts = self.boot_time_ns - manage_ts
#		cur_time = self.cur_time_ns - ts
#		cur_time = float(cur_time / 1000000000)
#
#		date = datetime.fromtimestamp(cur_time).strftime("%Y-%m-%d %H:%M:%S.%f")
#		nano_sec = date.split(" ")[1]
#		nano_sec = nano_sec.split(".")[1]
#
#		cur_time += int(nano_sec) / 1000
#		return datetime.fromtimestamp(cur_time).strftime("%Y-%m-%d %H:%M:%S")
#		return cur_time
	
	def __get_time2__(self, data, d_type):
		if d_type == 1:
			self.min_time = min(self.min_time, self.__get_time1__(data["manage_ts"]))
		else:
			self.min_time = min(self.min_time, self.__get_time0__(data["node_id"], data["ts"]))

#############################################################################
	def __query0__(self):
		sql = """
			select * from flow_id
		"""
		self.cursor.execute(sql)
		return self.cursor.fetchall()
	
	def __query1__(self):
		sql = """
			select * from result
		"""
		self.cursor.execute(sql)
		return self.cursor.fetchall()
	
	def __query2__(self):
		sql = """
			select * from metric;
		"""
		self.cursor.execute(sql)
		return self.cursor.fetchall()

	def __query3__(self):
		sql = """
			select * from result where node_id1=node_id2
		"""
		self.cursor.execute(sql)
		return self.cursor.fetchall()
	
	def __query5__(self):
		sql = """
			select * from result where node_id1=1 and node_id2=2
		"""
		self.cursor.execute(sql)
		return self.cursor.fetchall()
	
	def __query6__(self):
		sql = """
			select * from result where node_id1=1 and node_id2=3
		"""
		self.cursor.execute(sql)
		return self.cursor.fetchall()

	def __query7__(self):
		sql = """
			select * from result where node_id1=2 and node_id2=4
		"""
		self.cursor.execute(sql)
		return self.cursor.fetchall()
	
	def __query8__(self):
		sql = """
			select * from result where node_id1=3 and node_id2=4
		"""
		self.cursor.execute(sql)
		return self.cursor.fetchall()

##############################################################################
	def __draw__(self):
		key = defaultdict()
		rev_key = defaultdict()
		key_num = 0

		for i in range(4):
			if i == 0: datas = self.__query5__()
			elif i == 1: datas = self.__query6__()
			elif i == 2: datas = self.__query7__()
			else: datas = self.__query8__()
			for data in datas:
				key_ = str(data["node_id1"]) + "_" + str(data["node_id2"])
				if key.get(key_) == None: 
					key[key_] = key_num
					rev_key[key_num] = key_
					self.data[key_num] = []
					key_num += 1

				key_num_ = key[key_]
				self.data[key_num_].append([data["manage_ts"], data["diff_ts"]])
	
		for idx in range(key_num):
			with open("./result/" + str(rev_key[idx]), "w") as f:
				self.data[idx].sort()
				for data in self.data[idx]:
					diff = self.__get_time1__(data[0]) - self.min_time
					self.min_time_ = min(self.min_time_, diff)
					diff -= self.min_time_
					f.write(str(diff / 1000000000) + "," + str(data[1] / 1000000) + "\n")
	
	def __draw_local__(self):
		datas = self.__query3__()
		for data in datas:
			node_id = data["node_id1"]
			evt_type1 = data["evt_type1"]
			evt_type2 = data["evt_type2"]

			if node_id == 1 or node_id == 2: continue
			if evt_type1 > evt_type2: evt_type1, evt_type2 = evt_type2, evt_type1

			key = str(evt_type1) + "_" + str(evt_type2)
			if self.local_data.get(node_id) == None: self.local_data[node_id] = defaultdict()
			if self.local_data[node_id].get(key) == None: self.local_data[node_id][key] = []
			self.local_data[node_id][key].append([data["manage_ts"], data["diff_ts"]])
		
		for node_id in self.local_data.keys():
			for key in self.local_data[node_id].keys():
				evt_type1 = int(key.split("_")[0])
				evt_type2 = int(key.split("_")[1])
				with open("./result/" + str(node_id) + "_" + self.layer_info[evt_type1] + "_" + self.layer_info[evt_type2], "w") as f:
					self.local_data[node_id][key].sort()
					for data in self.local_data[node_id][key]:
						diff = self.__get_time1__(data[0]) - self.min_time
						self.min_time_ = min(self.min_time_, diff)
						diff -= self.min_time_
						f.write(str(diff / 1000000000) + "," + str(data[1] / 1000000) + "\n")

	def __draw_metric__(self):
		datas = self.__query2__()

		for data in datas:
			node_id = data["node_id"]
			pname = data["pname"]
			if self.metric_data.get(node_id) == None: self.metric_data[node_id] = defaultdict()
			if self.metric_data[node_id].get(pname) == None: self.metric_data[node_id][pname] = [[], []]

			self.metric_data[node_id][pname][0].append([data["ts"], data["cpu_usage"]])
			self.metric_data[node_id][pname][1].append([data["ts"], data["mem_usage"]])

		for node_id in self.metric_data.keys():
			for pname in self.metric_data[node_id].keys():
				with open("./result/" + str(node_id) + "_" + pname + "_" + "metric_cpu", "w") as f:
					for data in self.metric_data[node_id][pname][0]:
						diff = self.__get_time0__(node_id, data[0]) - self.min_time
						self.min_time_ = min(self.min_time_, diff)
						diff -= self.min_time_
						f.write(str(diff / 1000000000) + "," + str(data[1]) + "\n")
				
				with open("./result/" + str(node_id) + "_" + pname + "_" + "metric_mem", "w") as f:
					for data in self.metric_data[node_id][pname][1]:
						diff = self.__get_time0__(node_id, data[0]) - self.min_time
						self.min_time_ = min(self.min_time_, diff)
						diff -= self.min_time_
						f.write(str(diff / 1000000000) + "," + str(data[1]) + "\n")

#############################################################################
	def __main__(self):
		self.__connect__()
		self.__preprocess__()
		self.__draw__()
		self.__draw_local__()
#		self.__draw_metric__()

eg = ebpfGraph()
eg.__main__()
	
