import ctypes

class ebpfProcess:
	def __init__(self):
		self.files = ["3_iperf_metric_cpu", "3_iperf_metric_mem", "4_iperf_metric_cpu", "4_iperf_metric_mem"]
	
	def __process__(self):
		for fname in self.files:
			min_time = ctypes.c_uint64(-1).value
			datas = []
			with open(fname, "r") as f:
				line = f.readline()
				while line != None and line != "":
					data = line
					time = float(data.split(",")[0])
					latency = float(data.split(",")[1])

					min_time = min(min_time, time)
					time -= min_time	

					datas.append([time, latency])
					line = f.readline()
			
			with open(fname, "w") as f:
				for data in datas:
					f.write(str(data[0]) + "," + str(data[1] * 10) + "\n")

	def __main__(self):
		self.__process__()

ep = ebpfProcess()
ep.__main__()

				
