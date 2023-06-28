import os
import shutil

class ebpfDraw:
	def __init__(self, em, ed, fid, min_time, time):
		self.em = em
		self.ed = ed
		self.fid = fid
		self.time = time
		self.min_time = min_time

	def __draw_inter__(self, args):
		result_data = {}
		for i in range(4):
			if i == 0: datas = self.ed.__query1__(self.fid)
			elif i == 1: datas = self.ed.__query2__(self.fid)
			elif i == 2: datas = self.ed.__query3__(self.fid)
			elif i == 3: datas = self.ed.__query4__(self.fid)

			for data in datas:
				key = str(data["node_id1"]) + "_" + str(data["node_id2"]) + "_" + str(data["evt_type1"])
				if result_data.get(key) == None: result_data[key] = []
				result_data[key].append([data["manage_ts1"], data["diff_ts"]])

		for (key, value) in result_data.items():
			with open("./result/" + key, "w") as f:
				for data in value:
					manage_ts = data[0] - self.min_time
					manage_ts = manage_ts / 1000000000
					if float(args.min) <= manage_ts and manage_ts <= float(args.max):
						f.write(str(manage_ts) + "," + str(data[1] / 1000000) + "\n")

	def __draw_intra__(self, args):
		local_data = {}

		datas = self.ed.__query5__(self.fid)
		for data in datas:
			nid = data["node_id1"]
			et1 = data["evt_type1"]
			et2 = data["evt_type2"]

			if et1 == et2: continue

			if et1 > et2:
				et1, et2 = et2, et1

			key = str(et1) + "_" + str(et2)
			if local_data.get(nid) == None: local_data[nid] = {}
			if local_data[nid].get(key) == None: local_data[nid][key] = []
			local_data[nid][key].append([data["manage_ts1"], data["diff_ts"]])

		for nid in local_data.keys():
			for (key, value) in local_data[nid].items():
				et1 = int(key.split("_")[0])
				et2 = int(key.split("_")[1])
				if nid > 2:
					with open("./result/" + str(nid) + "_" + self.em.layer_info[et1] + "_" + self.em.layer_info[et2], "w") as f:
						for data in value:
							manage_ts = data[0] - self.min_time
							manage_ts = manage_ts / 1000000000
							if float(args.min) <= manage_ts and manage_ts <= float(args.max):
								f.write(str(manage_ts) + "," + str(data[1] / 1000000) + "\n")
				else:
					with open("./result/" + str(nid) + "_" + str(self.em.layer_info[et1]) + "_" + str(self.em.layer_info[et2]), "w") as f:
						for data in value:
							manage_ts = data[0] - self.min_time
							manage_ts = manage_ts / 1000000000
							if float(args.min) <= manage_ts and manage_ts <= float(args.max):
								f.write(str(manage_ts) + "," + str(data[1] / 1000000) + "\n")
	
	def __get_time__(self, nid, ts):
		server_ts = self.time[nid]["server_ts"]
		ts = ts - server_ts
		ts = ts + self.time[nid]["management_ts"]
		return ts
	
	def __draw_throughput_loss__(self, args):
		print("start")

		for node_id in range(1, 3):
			folder_name = "./result/" + str(node_id)
			if os.path.exists(folder_name) == True: shutil.rmtree(folder_name)
			os.mkdir(folder_name)

			for evt_type in range(0, 8):
				print("try to", node_id, evt_type)
				datas = self.ed.__query6__(self.fid, node_id, evt_type)
				if datas == None: print("nodata"); continue
				
				data_x = []; data_y = []
				data_x_loss = []; data_y_loss = []
				count_total = 0; count_loss = 0

				prev_ts = 0
				prev_data_len = 0

				for data in datas:
					ts = self.__get_time__(node_id, data["ts"])
					data_len = data["data_len"]; is_retrans = data["is_retrans"]

					if prev_ts != 0 and ts - prev_ts >= 1000000000 and is_retrans == 0:
						throughput = (data_len - prev_data_len) / ((ts - prev_ts) / 1000000000)
						throughput = throughput / 1000000

						if throughput >= 0:
							data_x.append((ts - self.min_time) / 1000000000)
							data_y.append(round(throughput, 3))
						
						prev_ts = ts
						prev_data_len = data_len

						data_x_loss.append((ts - self.min_time) / 1000000000)
						data_y_loss.append(round(float(count_loss / count_total), 3) * 100)

						count_total = 0; count_loss = 0

					if data["is_retrans"] == 0: count_total += 1
					if data["is_retrans"] == 1: count_loss += 1

					if prev_ts == 0 and is_retrans == 0: prev_ts = ts; prev_data_len = data_len

				fname = folder_name + "/" + str(evt_type) + "_throughput"
				fp = open(fname, "a")
				for (x, y) in zip(data_x, data_y):
					fp.write(str(x) + "," + str(y) + "\n")
				fp.close()

				fname = folder_name + "/" + str(evt_type) + "_loss"
				fp = open(fname, "a")
				for (x, y) in zip(data_x_loss, data_y_loss):
					fp.write(str(x) + "," + str(y) + "\n")
				fp.close()
						
	def __draw_metric__(self, args):		
		datas = self.ed.__query8__(self.fid)
		if datas == None: return
		
		for data in datas:
			node_id = data["node_id"]
			ts = self.__get_time__(data["node_id"], data["ts"]) - self.min_time
			if ts < 0: continue
			cpu_usage = data["cpu_usage"]
			mem_usage = data["mem_usage"]

			fname1 = "./result/" + str(node_id) + "_cpu"
			fname2 = "./result/" + str(node_id) + "_mem"

			if cpu_usage > 0.0:
				fp1 = open(fname1, "a")
				fp1.write(str(ts / 1000000000) + "," + str(cpu_usage) + "\n")
				fp1.close()

			if mem_usage > 0.0:
				fp2 = open(fname2, "a")
				fp2.write(str(ts / 1000000000) + "," + str(mem_usage) + "\n")
				fp2.close()








