import pymysql
import redis
import json
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

		self.pair_key = defaultdict()
		self.ports = set()

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
	
	def __insert0__(self, data):
		sql = "insert ignore into flow_id (src_addr, dst_addr, src_port, dst_port) values (%s, %s, %s, %s)"
		src_addr = self.__change_addr_to_str__(data.src_addr)
		dst_addr = self.__change_addr_to_str__(data.dst_addr)
		self.cursor.execute(sql, (src_addr, dst_addr, int(data.src_port), int(data.dst_port)))

		self.db.commit()

		sql = "select id from flow_id where src_addr=%s and dst_addr=%s and src_port=%s and dst_port=%s"
		self.cursor.execute(sql, (src_addr, dst_addr, int(data.src_port), int(data.dst_port)))
		return self.cursor.fetchall()[0]["id"]
	
	def __insert1__(self, data):
		flow_id = self.__insert0__(data)
		sql = "insert into log (flow_id, node_id, data_len, ts, evt_type) values (%s, %s, %s, %s, %s)"

		self.cursor.execute(sql, (flow_id, int(self.metadata["metadata_key"]), int(data.data_len), int(data.ts), int(data.evt_type)))
		self.db.commit()

		key1 = (self.__change_addr_to_str__(data.src_addr), data.src_port, self.__change_addr_to_str__(data.dst_addr), data.dst_port)
		key2 = (self.__change_addr_to_str__(data.dst_addr), data.dst_port, self.__change_addr_to_str__(data.src_addr), data.src_port)
		self.pair_key[key1] = flow_id
		self.pair_key[key2] = flow_id

	def __insert2__(self, data):
		sql = "insert into metric (flow_id, node_id, ts, pid, pname, port, cpu_usage, mem_usage) values (%s, %s, %s, %s, %s, %s, %s, %s)"

		connections = psutil.net_connections(kind = "inet")
		for connection in connections:
			laddr = connection.laddr
			raddr = connection.raddr
			if laddr.port in self.ports:
				try:
					if laddr == () or raddr == (): continue
					key = (laddr.ip, laddr.port, raddr.ip, raddr.port)
					if self.pair_key.get(key) == None: continue
					flow_id = self.pair_key[key]

					stat = psutil.Process(pid)
					ts = data.ts
					pid = connection.pid
					pname = stat.name()
					port = connection.laddr.port
					cpu_usage = float(stat.cpu_percent())
					mem_usage = float(stat.memory_percent())
					self.cursor.execute(sql, (flow_id, int(self.metadata["metadata_key"]), ts, pid, pname, port, cpu_usage, mem_usage))
					self.db.commit()
				except:
					pass
	
	def __close__(self):
		self.db.close()

############################################################################
	def __main__(self):
		self.__get_metadata__()
		self.__connect__()














