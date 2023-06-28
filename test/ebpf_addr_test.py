def __change_addr_to_str__(addr):
	addr_str = str(bin(int(addr)))[2:]
	print(addr_str)
	addr_str = addr_str.zfill(32)
	addr_str = addr_str[::-1]

	addr = []
	num = 1; ssum = 0
	for ch in addr_str:
		if ch == '1': ssum += num
		num = num * 2
		if num >= pow(2, 8):
			addr.append(ssum)
			num = 1; ssum = 0
	addr.append(ssum)

	addr = (str(addr[3]) + "." + str(addr[2]) + "." + str(addr[1]) + "." + str(addr[0]))
	return addr

print(__change_addr_to_str__(3372286218))
print(__change_addr_to_str__(16843018))
print(__change_addr_to_str__(453050634))

addr = int(input())
addr_str = bin(addr)[2:]
addr_str = addr_str.zfill(32)
print(addr_str)
