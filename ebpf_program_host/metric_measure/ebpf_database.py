import pymysql
import redis
import json
import time
import ctypes
import psutil
from collections import defaultdict

class ebpfDatabase:
	def __init__(self, args):
		self.args = args

		self.rd = redis.StrictRedis(host = self.args.redis_host, port = self.args.redis_port, db = 0)
		self.rd_key = self.args.redis_key
		self.rd_db_key = "database"

		self.metadata = None
		self.db_metadata = None

		self.db = None
		self.cursor = None

		self.flow_id = defaultdict()

		self.overlap_ports = set()
		self.overlap_pair_key = set()

	def __get_metadata__(self):
		self.metadata = self.rd.get(self.rd_key).decode("utf-8")
		self.metadata = dict(json.loads(self.metadata))

		self.db_metadata = self.rd.get(self.rd_db_key).decode("utf-8")
		self.db_metadata = dict(json.loads(self.db_metadata))
	
	def __change_addr_to_str__(self, addr):
		addr_str = str(bin(int(addr)))[2:]
		addr_str = addr_str.zfill(32)
		addr_str = addr_str[::-1]

		addr = []
		num = 1; ssum = 0
		for i in range(32):
			if addr_str[i] == "1": ssum += num
			num *= 2
			if num >= pow(2, 8):
				addr.append(ssum)
				num = 1; ssum = 0
		addr.append(ssum)
		addr = str(addr[0]) + "." + str(addr[1]) + "." + str(addr[2]) + "." + str(addr[3])
		return addr
	
############################################################################
	def __connect__(self):
		self.db = pymysql.connect(
				user = self.db_metadata["user"],
				passwd = self.db_metadata["passwd"],
				host = self.db_metadata["host"],
				db = self.db_metadata["db"],
				charset = "utf8"
			)
		self.cursor = self.db.cursor(pymysql.cursors.DictCursor)
	
	def __insert0__(self, data, ports):
		sql = "insert ignore into flow_id (src_addr, dst_addr, src_port, dst_port) values (%s, %s, %s, %s)"
		src_addr = self.__change_addr_to_str__(data.src_addr)
		dst_addr = self.__change_addr_to_str__(data.dst_addr)

		if src_addr != "10.20.17.235" and src_addr != "10.20.17.238": return -1
		if dst_addr != "10.20.17.235" and dst_addr != "10.20.17.238": return -1
		if self.flow_id.get((src_addr, dst_addr, int(data.src_port), int(data.dst_port))) != None:
			return self.flow_id[(src_addr, dst_addr, int(data.src_port), int(data.dst_port))]
		self.cursor.execute(sql, (src_addr, dst_addr, int(data.src_port), int(data.dst_port)))

		self.db.commit()

		if int(data.src_port) not in self.overlap_ports:
			self.overlap_ports.add(int(data.src_port))
			ports.put(int(data.src_port))
		if int(data.dst_port) not in self.overlap_ports:
			self.overlap_ports.add(int(data.dst_port))
			ports.put(int(data.dst_port))

		sql = "select id from flow_id where src_addr=%s and dst_addr=%s and src_port=%s and dst_port=%s"
		self.cursor.execute(sql, (src_addr, dst_addr, int(data.src_port), int(data.dst_port)))
		flow_id = self.cursor.fetchall()[0]["id"]
		self.flow_id[(src_addr, dst_addr, int(data.src_port), int(data.dst_port))] = flow_id
		return flow_id
	
	def __insert1__(self, data, queue, ports, pair_key):
		flow_id = self.__insert0__(data, ports)
		if flow_id == -1: return
		
		queue.put((flow_id, int(self.metadata["metadata_key"]), int(data.start_data_len), int(data.data_len), int(data.ts), int(data.evt_type)))
		key1 = (self.__change_addr_to_str__(data.src_addr), data.src_port, self.__change_addr_to_str__(data.dst_addr), data.dst_port)
		key2 = (self.__change_addr_to_str__(data.dst_addr), data.dst_port, self.__change_addr_to_str__(data.src_addr), data.src_port)

		if (key1, flow_id) not in self.overlap_pair_key:
			self.overlap_pair_key.add((key1, flow_id))
			pair_key.put(key1, flow_id)
		if (key2, flow_id) not in self.overlap_pair_key:
			self.overlap_pair_key.add((key2, flow_id))
			pair_key.put((key2, flow_id))

	def __insert2__(self, ports, pair_key):
		if len(ports) <= 0: return

		sql = "insert into metric (flow_id, node_id, ts, pid, pname, port, cpu_usage, mem_usage) values (%s, %s, %s, %s, %s, %s, %s, %s)"

		with open("/proc/uptime", "r") as f:
			data = f.readline()
			ts = int(float(data.split()[0])) * 1000000000 + int(float(data.split()[1]))

		connections = psutil.net_connections(kind = "inet")
		for connection in connections:
			laddr = connection.laddr
			raddr = connection.raddr
			if laddr.port in ports:
				try:
					if laddr == () or raddr == (): continue
					key = (laddr.ip, laddr.port, raddr.ip, raddr.port)
					if pair_key.get(key) == None: continue
					flow_id = pair_key[key]

					stat = psutil.Process(pid)
					ts = ts
					pid = connection.pid
					pname = stat.name()
					port = connection.laddr.port
					cpu_usage = float(stat.cpu_percent())
					mem_usage = float(stat.memory_percent())
					self.cursor.execute(sql, (flow_id, int(self.metadata["metadata_key"]), ts, pid, pname, port, cpu_usage, mem_usage))
					self.db.commit()
				except:
					pass
	
	def __insert3__(self, data):
		if len(data) <= 0: return
		sql = "insert into log (flow_id, node_id, start_data_len, data_len, ts, evt_type) values (%s, %s, %s, %s, %s, %s)"
		self.cursor.executemany(sql, data)
		self.db.commit()
		
	def __close__(self):
		self.db.close()

############################################################################
	def __main__(self):
		self.__get_metadata__()
		self.__connect__()














