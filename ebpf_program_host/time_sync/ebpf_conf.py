import argparse

class ebpfConf:
	def __init__(self):
		self.parser = argparse.ArgumentParser(description = "Ebpf Sync Time Argv")
		self.parser.add_argument("--redis_host", required = True, help = "redis server address")
		self.parser.add_argument("--redis_port", required = True, help = "redis server port")
		self.parser.add_argument("--redis_key", required = True, help = "redis metadata key")

		self.args = self.parser.parse_args()

	def __main__(self):
		return self.args

