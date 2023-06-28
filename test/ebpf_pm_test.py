import os
import time
import paramiko as pm

client = pm.SSHClient()
client.load_system_host_keys()
client.load_host_keys(os.path.expanduser("~/.ssh/known_hosts"))
client.set_missing_host_key_policy(pm.AutoAddPolicy())
client.connect(hostname = "10.1.1.2", port = 51111, username = "sonic", password = "skwx4216@!")

def waitstream(channel):
	outdata = ""
	errdata = ""

	while channel.recv_ready():
		outdata += str(channel.recv(1000))
	while channel.recv_stderr_ready():
		errdata += str(channel.recv_stderr(1000))
	
	return outdata, errdata

channel = client.invoke_shell()
waitstream(channel)

channel.send("sudo python3 ~/test/ebpf_test.py\n")
channel.send("skwx4216@!\n")
waitstream(channel)

while True:
	time.sleep(1)
	outdata, errdata = waitstream(channel)
	print(outdata)
	if outdata.find("termination") != -1: break

#channel.send("df -h\n")
#waitstream()
