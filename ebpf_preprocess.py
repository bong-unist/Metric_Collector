import os
import sys
import redis
import json
import time

import ebpf_terminal
import ebpf_database

class ebpfPreprocess:
	def __init__(self, ebpf_conf):
		self.ebpf_conf = ebpf_conf
		self.connect_info = self.ebpf_conf.connect_info
		self.management_server_info = self.ebpf_conf.management_server_info
		self.sampling_info = self.ebpf_conf.sampling_info
		self.database_info = self.ebpf_conf.database_info
		self.redis_info = self.ebpf_conf.redis_info

		self.rd = redis.StrictRedis(host = self.redis_info["host"], port = self.redis_info["port"], db = 0)

		self.ed = ebpf_database.ebpfDatabase(self.ebpf_conf)
		self.ed.__connect__()
		
	def __set_metadata__(self):
		key1 = "servers"
		key2 = "metadata_key"
		key3 = "sampling"
		key4 = "database"

		for connect_info in self.connect_info[key1]:
			if connect_info.get("iscontainer") != None: continue
			json_connect_info = json.dumps(connect_info, ensure_ascii = False).encode("utf-8")
			metadata_key = connect_info[key2]
			self.rd.set(metadata_key, json_connect_info)

		for connect_info in self.connect_info[key1]:
			addr = -1 if connect_info.get("address") == None else connect_info["address"]
			if connect_info.get("iscontainer") != None: metadata_key = -1
			else: metadata_key = connect_info["metadata_key"]
			is_vm = -1 if connect_info.get("isvm") == None else connect_info["isvm"]
			is_container = -1 if connect_info.get("iscontainer") == None else connect_info["iscontainer"]
			if addr != -1: self.ed.__update_server_info__(metadata_key, addr, is_vm, is_container)

			if connect_info.get("other_address") != None:
				for addr in connect_info["other_address"]:
					self.ed.__update_server_info__(-1, addr, -1, -1, metadata_key)
			
			if connect_info.get("container_address") != None:
				for addr in connect_info["container_address"]:
					self.ed.__update_server_info__(-1, addr, is_vm, is_container)

		json_sampling_info = json.dumps(self.sampling_info, ensure_ascii = False).encode("utf-8")
		self.rd.set(key3, json_sampling_info)

		json_database_info = json.dumps(self.database_info, ensure_ascii = False).encode("utf-8")
		self.rd.set(key4, json_database_info)

	def __set_table__(self):
		sql = "drop table if exists flow_id"
		self.ed.cursor.execute(sql)

		sql = """
			create table flow_id (
				id bigint NOT NULL AUTO_INCREMENT PRIMARY KEY,
				src_addr varchar(32) NOT NULL,
				dst_addr varchar(32) NOT NULL,
				src_port int NOT NULL,
				dst_port int NOT NULL,
				unique index(src_addr, dst_addr, src_port, dst_port)
			)
		"""
		self.ed.cursor.execute(sql)

		sql = "drop table if exists log"
		self.ed.cursor.execute(sql)

		sql = """
			create table log (
				flow_id bigint NOT NULL,
				node_id int NOT NULL,
				data_len bigint NOT NULL,
				ts bigint NOT NULL,
				evt_type int NOT NULL,
				tid bigint NOT NULL,
				start_seq bigint NOT NULL,
				cur_seq bigint NOT NULL,
				cpuid int NOT NULL,
				is_retrans int default 0,
				index idx_key(flow_id, node_id, data_len)
			)
		"""
		self.ed.cursor.execute(sql)

		sql = "drop table if exists metric"
		self.ed.cursor.execute(sql)

		sql = """
			create table metric (
				flow_id bigint NOT NULL,
				node_id int NOT NULL,
				ts bigint NOT NULL,
				pid int NOT NULL,
				pname varchar(32) NOT NULL,
				port int NOT NULL,
				cpu_usage double NOT NULL,
				mem_usage double NOT NULL
			)
		"""
		self.ed.cursor.execute(sql)

		sql = "drop table if exists statistical_data"
		self.ed.cursor.execute(sql)

		sql = """
			create table statistical_data (
				flow_id bigint NOT NULL,
				node_id int NOT NULL,
				manage_ts bigint NOT NULL,
				throughput double NOT NULL,
				loss_rate double NOT NULL,
				evt_type int NOT NULL
			)
		"""
		self.ed.cursor.execute(sql)

		sql = "drop table if exists server_info"
		self.ed.cursor.execute(sql)

		sql = """
			create table server_info (
				node_id int NOT NULL,
				addr varchar(32) NOT NULL,
				is_vm int default -1,
				is_container int default -1,
				is_other int default -1
			)
		"""
		self.ed.cursor.execute(sql)
		
		self.ed.db.commit()

	def __auto_install__(self):
		key1 = "servers"

		for connect_info in self.connect_info[key1]:
			if connect_info.get("iscontainer") != None: continue
			et = ebpf_terminal.ebpfTerminal(connect_info)
			et.__preprocess__()

			command1 = "scp -r -P " + str(self.management_server_info["port"])
			command2 = str(self.management_server_info["username"]) + "@" + str(self.management_server_info["address"]) + ":~/"
			command3 = None
			
			if connect_info.get("isvm") == None:
				command3 = "Metric_Collector_ver6/ebpf_program_vm ~/"
#				command3 = "Metric_Collector_ver6/ebpf_program_host ~/"
			else:
				command3 = "Metric_Collector_ver6/ebpf_program_vm ~/"

			command = command1 + " " + command2 + command3
			print(command)
			et.__mainprocess__(command)
			time.sleep(0.1)
			et.__mainprocess__(self.management_server_info["password"])
			time.sleep(0.1)

#################################################################################################
	def __main__(self):
		self.__set_table__()
		self.__set_metadata__()
		self.__auto_install__()
		
