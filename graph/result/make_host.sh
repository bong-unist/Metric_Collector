#!/bin/bash

gnuplot make_host_analyzer_delay
gnuplot make_host_analyzer_all_delay
gnuplot make_host_analyzer_hh_layer_delay
gnuplot make_host_analyzer_h_send_layer_delay
gnuplot make_host_analyzer_h_recv_layer_delay
gnuplot make_host_throughput_1
gnuplot make_host_throughput_2
gnuplot make_host_metric_cpu_1
gnuplot make_host_metric_cpu_2
gnuplot make_host_metric_mem_1
gnuplot make_host_metric_mem_2
gnuplot make_host_loss_1
gnuplot make_host_loss_2

scp -P 51111 analyzer_delay.png sonic@10.20.16.135:~/
scp -P 51111 analyzer_all_delay.png sonic@10.20.16.135:~/
#scp -P 51111 analyzer_layer_delay.png sonic@10.1.1.200:~/
scp -P 51111 analyzer_h_layer_delay.png sonic@10.20.16.135:~/
scp -P 51111 analyzer_hh_layer_delay.png sonic@10.20.16.135:~/
#scp -P 51111 analyzer_send_layer_delay.png sonic@10.1.1.200:~/
#scp -P 51111 analyzer_recv_layer_delay.png sonic@10.1.1.200:~/
scp -P 51111 analyzer_h_send_layer_delay.png sonic@10.20.16.135:~/
scp -P 51111 analyzer_h_recv_layer_delay.png sonic@10.20.16.135:~/ 
scp -P 51111 1_throughput.png sonic@10.20.16.135:~/
scp -P 51111 2_throughput.png sonic@10.20.16.135:~/
scp -P 51111 1_metric_cpu.png sonic@10.20.16.135:~/
scp -P 51111 2_metric_cpu.png sonic@10.20.16.135:~/
scp -P 51111 1_metric_mem.png sonic@10.20.16.135:~/
scp -P 51111 2_metric_mem.png sonic@10.20.16.135:~/
scp -P 51111 1_loss.png sonic@10.20.16.135:~/
scp -P 51111 2_loss.png sonic@10.20.16.135:~/

