import yaml
from collections import defaultdict

class ebpfConf:
	def __init__(self):
		self.file_list = ["conf/management_server_info.yaml", "conf/sampling_info.yaml", "conf/connect_info.yaml", "conf/database_info.yaml", "conf/redis_info.yaml"]

		self.management_server_info = defaultdict()
		self.sampling_info = defaultdict()
		self.connect_info = defaultdict()
		self.database_info = defaultdict()
		self.redis_info = defaultdict()

	def __read_conf__(self):
		for idx, file_name in enumerate(self.file_list):
			with open(file_name) as f:
				if idx == 0: self.management_server_info = yaml.load(f, Loader = yaml.FullLoader)
				elif idx == 1: self.sampling_info = yaml.load(f, Loader = yaml.FullLoader)
				elif idx == 2: self.connect_info = yaml.load(f, Loader = yaml.FullLoader)
				elif idx == 3: self.database_info = yaml.load(f, Loader = yaml.FullLoader)
				elif idx == 4: self.redis_info = yaml.load(f, Loader = yaml.FullLoader)
	
	def __main__(self):
		self.__read_conf__()

			
