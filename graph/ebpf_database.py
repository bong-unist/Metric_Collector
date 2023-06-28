import pymysql

class ebpfDatabase:
	def __init__(self, em, flowid_table, result_table, log_table = "log", metric_table = "metric"):
		self.em = em
		self.flowid_table = flowid_table
		self.result_table = result_table
		self.log_table = log_table
		self.metric_table = metric_table
	
	def __query0__(self):
		sql = """
			select * from {}
		""".format(self.flowid_table)
		self.em.cursor.execute(sql)
		return self.em.cursor.fetchall()
	
	def __query1__(self, fid):
		sql = """
			select * from {} where node_id1=1 and node_id2=2 and flow_id=%s
		""".format(self.result_table)
		self.em.cursor.execute(sql, (fid))
		return self.em.cursor.fetchall()
	
	def __query2__(self, fid):
		sql = """
			select * from {} where node_id1=1 and node_id2=3 and flow_id=%s
		""".format(self.result_table)
		self.em.cursor.execute(sql, (fid))
		return self.em.cursor.fetchall()
	
	def __query3__(self, fid):
		sql = """
			select * from {} where node_id1=2 and node_id2=4 and flow_id=%s
		""".format(self.result_table)
		self.em.cursor.execute(sql, (fid))
		return self.em.cursor.fetchall()
	
	def __query4__(self, fid):
		sql = """
			select * from {} where node_id1=3 and node_id2=4 and flow_id=%s
		""".format(self.result_table)
		self.em.cursor.execute(sql, (fid))
		return self.em.cursor.fetchall()
	
	def __query5__(self, fid):
		sql = """
			select * from {} where node_id1=node_id2 and flow_id=%s
		""".format(self.result_table)
		self.em.cursor.execute(sql, (fid))
		return self.em.cursor.fetchall()

	def __query6__(self, fid, node_id, evt_type):
		sql = """
			select * from {} where node_id=%s and evt_type=%s and flow_id=%s order by ts
		""".format(self.log_table)
		self.em.cursor.execute(sql, (node_id, evt_type, fid))
		return self.em.cursor.fetchall()
	
	def __query8__(self, fid):
		sql = """
			select * from {} where flow_id=%s
		""".format(self.metric_table)
		self.em.cursor.execute(sql, (fid))
		return self.em.cursor.fetchall()

	def __query_time__(self, fid, flag = 0):
		if flag == 0:
			sql = """
				select min(manage_ts1) from {} where flow_id=%s
			""".format(self.result_table)
			self.em.cursor.execute(sql, (fid))
		else:
			sql = """
				select min(manage_ts2) from {} where flow_id=%s
			""".format(self.result_table)
			self.em.cursor.execute(sql, (fid))
		return self.em.cursor.fetchall()
	
	def __query_total__(self, fid):
		sql = """
			select * from {} where flow_id=%s
		""".format(self.log_table)
		self.em.cursor.execute(sql, (fid))
		return self.em.cursor.fetchall()


