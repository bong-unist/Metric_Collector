from bcc import BPF
import logging
import multiprocessing

import ebpf_code

ec = ebpf_code.ebpfCode()
code = ec.__main__()

def event_callback(ctx, data, size):
    data = b["event_ringbuf"].event(data)
    print("---------------")
    print(data.src_addr)
    print(data.dst_addr)
    print(data.src_port)
    print(data.dst_port)
    print(data.cycle)
    print(data.data_len)
    print(data.evt_type)
    print("---------------")

b = BPF(text = code, cflags = ["-DNUM_CPUS=%d" % multiprocessing.cpu_count()])
b["event_ringbuf"].open_ring_buffer(event_callback)

func_name = ["sock_sendmsg", "dev_queue_xmit", "sock_recvmsg", "tcp_v4_rcv"]

for name in func_name:
    if name.find("sock") != -1:
        b.attach_kprobe(event = name, fn_name = "___" + name)
        b.attach_kretprobe(event = name, fn_name = "__" + name)
    else:
        b.attach_kprobe(event = name, fn_name = "__" + name)

while True:
    try:
        #b.trace_print()
        b.ring_buffer_consume()
    except:
        logging.exception("message")
