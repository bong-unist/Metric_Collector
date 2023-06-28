import pymysql
import json
import ctypes

import ebpf_metadata
import ebpf_database
import ebpf_draw

import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--min", required = False, default = -1, help = "Min Sec")
parser.add_argument("--max", required = False, default = 10000000, help = "Max Sec")
parser.add_argument("--flowid_table", required = False, default = "flow_id", help = "Flowid Table")
parser.add_argument("--result_table", required = False, default = "result", help = "Result Table")
parser.add_argument("--log_table", required = False, default = "log", help = "Log Table")
parser.add_argument("--metric_table", required = False, default = "metric", help = "Metric Table")
parser.add_argument("--flowid", required = False, default = -1, help = "flowid")
args = parser.parse_args()

class ebpfGraph:
	def __init__(self):
		self.em = ebpf_metadata.ebpfMetadata()
		self.ed = ebpf_database.ebpfDatabase(self.em, args.flowid_table, args.result_table, args.log_table, args.metric_table)

		self.flow_id = {}
		self.time = {}
		self.min_time = ctypes.c_uint64(-1).value

		self.user_fid = None

		self.__preprocess__()
		self.edw = ebpf_draw.ebpfDraw(self.em, self.ed, self.user_fid, self.min_time, self.time)
	
	def __get_time__(self, nid, ts):
		server_ts = self.time[nid]["server_ts"]
		ts = ts - server_ts
		ts = ts + self.time[nid]["management_ts"]
		self.min_time = min(self.min_time, ts)
	
	def __preprocess__(self):
		datas = self.ed.__query0__()
		if not datas: return None
		
		for data in datas:
			self.flow_id[data["id"]] = [data["src_addr"], data["dst_addr"], data["src_port"], data["dst_port"]]
		for i in range(1, 5):
			data = self.em.rd.get(self.em.connect_info[i]).decode("utf-8")
			self.time[i] = dict(json.loads(data))

		if args.flowid != -1:
			self.user_fid = args.flowid
		else:
			for (key, value) in self.flow_id.items():
				print(key, value)
			self.user_fid = int(input("Select which flow_id you want? "))

		datas = self.ed.__query_total__(self.user_fid)
		for data in datas:
			self.__get_time__(data["node_id"], data["ts"])

		self.min_time = min(self.min_time, self.ed.__query_time__(self.user_fid, 0)[0]["min(manage_ts1)"])
		self.min_time = min(self.min_time, self.ed.__query_time__(self.user_fid, 1)[0]["min(manage_ts2)"])
	
	def __main__(self):
		self.edw.__draw_inter__(args)
		self.edw.__draw_intra__(args)
		self.edw.__draw_throughput_loss__(args)
		self.edw.__draw_metric__(args)
		
if __name__ == "__main__":
	eg = ebpfGraph()
	eg.__main__()




