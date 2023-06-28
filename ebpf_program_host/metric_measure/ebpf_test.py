from bcc import BPF
import multiprocessing
import logging
from collections import defaultdict
import socket

import ebpf_code

ec = ebpf_code.ebpfCode()
code = ec.__main__()

func_name = ["virtio_dev_tx_split", "virtio_dev_tx_packed", "virtio_dev_rx_split", "virtio_dev_rx_packed", "mlx5_rx_burst_vec", "mlx5_tx_burst_none_empw"]
library_path = "/usr/local/lib/x86_64-linux-gnu/"
library_name = defaultdict()
attach_pos = defaultdict()

def event_callback(ctx, data, size):
    data = b["event_ringbuf"].event(data)
    print("------------------")
    print(data.src_addr)
    print(data.dst_addr)
    print(socket.ntohs(data.src_port))
    print(socket.ntohs(data.dst_port))
    print(data.cycle)
    print(data.data_len)
    print(data.evt_type)
    print("------------------")

def set_variable():
    global library_name, attach_pos

    library_name["virtio_dev_tx_split"] = "librte_vhost.so"
    library_name["mlx5_tx_burst_none_empw"] = "librte_net_mlx5.so"
    library_name["virtio_dev_tx_packed"] = "librte_vhost.so"
    library_name["mlx5_rx_burst_vec"] = "librte_net_mlx5.so"
    library_name["virtio_dev_rx_split"] = "librte_vhost.so"
    library_name["virtio_dev_rx_packed"] = "librte_vhost.so"

    attach_pos["virtio_dev_tx_split"] = "ret"
    attach_pos["mlx5_tx_burst_none_empw"] = "entry"
    attach_pos["virtio_dev_tx_packed"] = "ret"
    attach_pos["mlx5_rx_burst_vec"] = "ret"
    attach_pos["virtio_dev_rx_split"] = "entry"
    attach_pos["virtio_dev_rx_packed"] = "entry"

def attach_function():
    global func_name, library_path, library_name, attach_pos

    for name in func_name:
        if attach_pos[name] == "entry":
            b.attach_uprobe(name = library_path + library_name[name], sym = name, fn_name = name)
        elif attach_pos[name] == "ret":
            b.attach_uretprobe(name = library_path + library_name[name], sym = name, fn_name = name)

if __name__ == "__main__":
    b = BPF(text = code, cflags = ["-DNUM_CPUS=%d" % multiprocessing.cpu_count()])
    b["event_ringbuf"].open_ring_buffer(event_callback)

    set_variable()
    attach_function()

    while True:
        try:
            #b.trace_print()
            b.ring_buffer_consume()
        except:
            logging.exception("message")
            







