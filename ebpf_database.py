import pymysql
import time
from collections import defaultdict

class ebpfDatabase:
	def __init__(self, ebpf_conf):
		self.ebpf_conf = ebpf_conf
		self.db_metadata = self.ebpf_conf.database_info
		
		self.db = None
		self.cursor = None

		self.data = defaultdict()
		self.last_send_time = defaultdict()

		self.statistical_data = []
		self.last_send_time_statistical_data = time.time()

#####################################################################
	def __connect__(self):
		self.db = pymysql.connect(
			user = self.db_metadata["user"],
			passwd = self.db_metadata["passwd"],
			host = self.db_metadata["host"],
			db = self.db_metadata["db"],
			charset = "utf8"
		)
		self.cursor = self.db.cursor(pymysql.cursors.DictCursor)

	def __create__(self):
		sql = """create table if not exists result (
				id bigint NOT NULL AUTO_INCREMENT PRIMARY KEY,
				flow_id bigint NOT NULL,
				node_id1 int NOT NULL,
				node_id2 int NOT NULL,
				data_len1 bigint NOT NULL,
				data_len2 bigint NOT NULL,
				diff_ts bigint NOT NULL,
				manage_ts1 bigint NOT NULL,
				manage_ts2 bigint NOT NULL,
				evt_type1 int NOT NULL,
				evt_type2 int NOT NULL,
				unique index (flow_id, node_id1, node_id2, data_len1, data_len2, evt_type1, evt_type2))"""
		self.cursor.execute(sql)
		self.db.commit()

	def __delete__(self):
		sql = "drop tables if exists result"
		self.cursor.execute(sql)

	def __close__(self):
		self.db.close()
	
	def __reconnect__(self):
		self.__close__()
		self.__connect__()

####################################################################
	def __update_server_info__(self, metadata_key, address, is_vm, is_container, is_other = -1):
		sql = """
			insert into server_info (node_id, addr, is_vm, is_container, is_other) values (%s, %s, %s, %s, %s)
		"""

		self.cursor.execute(sql, (metadata_key, address, is_vm, is_container, is_other))
		self.db.commit()

	def __get_server_info__(self):
		sql = """
			select * from server_info
		"""
		
		self.cursor.execute(sql)
		return self.cursor.fetchall()

	def __query0__(self):
		sql = """
			select * from flow_id order by id
		"""

		self.cursor.execute(sql)
		return self.cursor.fetchall()

	def __query1__(self, flow_id, node_id, data, size, evt_type):
		sql = """
			select * from log where flow_id=%s and node_id=%s and (data_len > %s and data_len <= %s) and evt_type=%s and is_retrans=0 order by data_len
		"""
		self.cursor.execute(sql, (flow_id, node_id, data, data + size, evt_type))
		return self.cursor.fetchall()
	
	def __query2__(self, flow_id, node_id):
		sql = """
			select DISTINCT(evt_type) from log where flow_id=%s and node_id=%s and is_retrans=0 order by evt_type
		"""
		self.cursor.execute(sql, (flow_id, node_id))
		return self.cursor.fetchall()

	def __query3__(self, flow_id, node_id, data, size, evt_type):
		sql = """
			select * from log where flow_id=%s and node_id=%s and (data_len > %s and data_len <= %s) and evt_type=%s and is_retrans=0 order by data_len
		"""
		self.cursor.execute(sql, (flow_id, node_id, data, data + size, evt_type))
		return self.cursor.fetchall()

	def __query4__(self, sid, node_id1, node_id2, data1, data2, diff_ts, manage_ts1, manage_ts2):
		if self.data.get(sid) == None: self.data[sid] = []; self.last_send_time[sid] = 0
		self.data[sid].append((data1["flow_id"], node_id1, node_id2, data1["data_len"], data2["data_len"], diff_ts, manage_ts1, manage_ts2, data1["evt_type"], data2["evt_type"]))

		if len(self.data[sid]) < 100: return

		sql = """
			insert ignore into result (flow_id, node_id1, node_id2, data_len1, data_len2, diff_ts, manage_ts1, manage_ts2, evt_type1, evt_type2) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
		"""
		self.cursor.executemany(sql, self.data[sid])
		self.db.commit()

		self.data[sid] = []
		self.last_send_time[sid] = time.time()

	def __query5__(self, sid):
		if self.last_send_time.get(sid) == None: return
		if time.time() - self.last_send_time[sid] < 10: return
		
		sql = """
			insert ignore into result (flow_id, node_id1, node_id2, data_len1, data_len2, diff_ts, manage_ts1, manage_ts2, evt_type1, evt_type2) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
		"""
		self.cursor.executemany(sql, self.data[sid])
		self.db.commit()

		self.data[sid] = []
		self.last_send_time[sid] = time.time()

	def __query6__(self, data):
		self.statistical_data.append(data)

		if len(self.statistical_data) < 100 and time.time() - self.last_send_time_statistical_data < 1000000000: return

		sql = """
			insert ignore into statistical_data (flow_id, node_id, manage_ts, throughput, loss_rate, evt_type) values (%s, %s, %s, %s, %s, %s)
		"""
		self.cursor.executemany(sql, self.statistical_data)
		self.db.commit()

		self.statistical_data = []
		self.last_send_time_statistical_data = time.time()

	def __query7__(self):
		if len(self.statistical_data) == 0: return

		sql = """
            insert ignore into statistical_data (flow_id, node_id, manage_ts, throughput, loss_rate, evt_type) values (%s, %s, %s, %s, %s, %s)
        """
		self.cursor.executemany(sql, self.statistical_data)
		self.db.commit()

		self.statistical_data = []
		self.last_send_time_statistical_data = time.time()

	def __get_flow_info__(self, fid):
		sql = """
			select * from flow_id where id=%s
		"""
		self.cursor.execute(sql, fid)
		return self.cursor.fetchall()


			
