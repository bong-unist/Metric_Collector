import pymysql

class ebpfDatabase:
	def __init__(self, ebpf_conf):
		self.ebpf_conf = ebpf_conf
		self.db_metadata = self.ebpf_conf.database_info
		
		self.db = None
		self.cursor = None

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
				manage_ts bigint NOT NULL,
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
	def __query0__(self):
		sql = """
			select * from flow_id where src_port=5001 or dst_port=5001
		"""
		self.cursor.execute(sql)
		return self.cursor.fetchall()

	def __query1__(self, flow_id, node_id, data, size):
		sql = """
			select * from log where flow_id=%s and node_id=%s and (data_len > %s and data_len <= %s)
		"""
		self.cursor.execute(sql, (flow_id, node_id, data, data + size))
		return self.cursor.fetchall()

	def __query2__(self, node_id, data, size):
		sql = """
			select * from log where flow_id=%s and node_id=%s and (data_len > %s and data_len <= %s)
		"""
		self.cursor.execute(sql, (data["flow_id"], node_id, data["data_len"] - size, data["data_len"] + size))
		return self.cursor.fetchall()

	def __query3__(self, node_id1, node_id2, data1, data2, diff_ts, manage_ts):
		if diff_ts >= 2000000000: return
		sql = """
			insert ignore into result (flow_id, node_id1, node_id2, data_len1, data_len2, diff_ts, manage_ts, evt_type1, evt_type2) values (%s, %s, %s, %s, %s, %s, %s, %s, %s)
		"""
		if node_id1 > node_id2:
			node_id1, node_id2 = node_id2, node_id1
			data1, data2 = data2, data1

		self.__create__()
		self.cursor.execute(sql, (data1["flow_id"], node_id1, node_id2, data1["data_len"], data2["data_len"], diff_ts, manage_ts, data1["evt_type"], data2["evt_type"]))
		self.db.commit()

	def __query4__(self, node_id, data, size):
		sql = """
			select * from log where flow_id=%s and node_id=%s and (data_len > %s and data_len <= %s) and evt_type!=%s
		"""
		self.cursor.execute(sql, (data["flow_id"], node_id, data["data_len"] - size, data["data_len"] + size, data["evt_type"]))
		return self.cursor.fetchall()
