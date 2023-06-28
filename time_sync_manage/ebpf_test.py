import ebpf_python 
import ebpf_code
import ebpf_conf

if __name__ == "__main__":
	ec = ebpf_conf.ebpfConf()
	ep = ebpf_python.ebpfPython(ec)
