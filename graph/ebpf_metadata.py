import pymysql
import redis
from collections import defaultdict

class ebpfMetadata:
	def __init__(self):
		self.database_info = defaultdict()
		self.redis_info = defaultdict()
		self.connect_info = defaultdict()
		self.layer_info = defaultdict()
		self.h_layer_info = defaultdict()

		self.database_info["user"] = "bw"
		self.database_info["passwd"] = "qhd7812"
		self.database_info["host"] = "10.20.24.117"
		self.database_info["db"] = "metric"

		self.redis_info["host"] = "10.20.24.117"
		self.redis_info["port"] = 6379

		self.connect_info[1] = "10.1.1.1"
		self.connect_info[2] = "10.1.1.2"
		self.connect_info[3] = "10.1.1.26"
		self.connect_info[4] = "10.1.1.27"

		self.layer_info[0] = "sock"
		self.layer_info[1] = "tcp"
		self.layer_info[2] = "ip"
		self.layer_info[3] = "driver"
		self.layer_info[4] = "sock"
		self.layer_info[5] = "tcp"
		self.layer_info[6] = "ip"
		self.layer_info[7] = "driver"

		self.h_layer_info[0] = "tx_split"
		self.h_layer_info[1] = "tx_packed"
		self.h_layer_info[2] = "mlx5_rx"
		self.h_layer_info[3] = "rx_split"
		self.h_layer_info[4] = "rx_packed"
		self.h_layer_info[5] = "mlx5_tx"

		self.rd = redis.StrictRedis(host = self.redis_info["host"], port = self.redis_info["port"], db = 0)
		self.db = pymysql.connect(
				user = self.database_info["user"],
				passwd = self.database_info["passwd"],
				host = self.database_info["host"],
				db = self.database_info["db"],
				charset = "utf8"
			)
		self.cursor = self.db.cursor(pymysql.cursors.DictCursor)

