import pymysql
import threading as th
import time

def __test__(node_id):
	time.sleep(10)

	db = pymysql.connect(
			user = "bw",
			passwd = "qhd7812",
			host = "10.1.1.201",
			db = "metric",
			charset = "utf8"
		)
	cursor = db.cursor(pymysql.cursors.DictCursor)

	sql = """
		select * from log where flow_id=%s and node_id=%s and (data_len > %s and data_len <= %s) order by data_len
	"""

	data_len = 0

	for i in range(10):
		st = time.time()
		cursor.execute(sql, (1, node_id, data_len, data_len + 10000000))
		data = cursor.fetchall()
		et = time.time()
		data_len += 10000000
		print("server {}, load latency = {}, len = {}, data_len = {}".format(node_id, et - st, len(data), data_len))

if __name__ == "__main__":
	for i in range(1, 5):
		th_ = th.Thread(target = __test__, args = (i, ))
		th_.start()
	th_.join()
	
