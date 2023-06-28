import pymysql

db = pymysql.connect(
		user = "bw",
		passwd = "qhd7812",
		host = "10.1.1.201",
		db = "metric",
		charset = "utf8"
	)

cursor = db.cursor(pymysql.cursors.DictCursor)

#drop_sql = "drop tables if exists {}"
#create_sql = """create table {} (
#                id bigint NOT NULL AUTO_INCREMENT PRIMARY KEY,
#                src_addr varchar(32) NOT NULL,
#                dst_addr varchar(32) NOT NULL,
#                src_port int NOT NULL,
#                dst_port int NOT NULL,
#                data_len bigint NOT NULL,
#                ts bigint NOT NULL,
#                evt_type int NOT NULL)"""
#insert_sql = "insert into {}(src_addr, dst_addr, src_port, dst_port, data_len, ts, evt_type) values (%s, %s, %s, %s, %s, %s, %s)"
#
#cursor.execute(drop_sql.format("test"))
#cursor.execute(create_sql.format("test"))
#cursor.execute(insert_sql.format("test"), ("127.0.0.1", "127.0.0.1", 16, 16, 123, 123, 1))
#db.commit()

sql = """
	select * from {} where (data_len >= %s and data_len < %s)
"""

cursor.execute(sql.format("node1"), (0, 100000))
print(cursor.fetchall())
