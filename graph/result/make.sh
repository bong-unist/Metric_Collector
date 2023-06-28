#!/bin/bash

gnuplot make_analyzer_delay
#gnuplot make_analyzer_layer_delay
gnuplot make_analyzer_all_delay
gnuplot make_analyzer_h_layer_delay
gnuplot make_analyzer_hh_layer_delay
#gnuplot make_analyzer_send_layer_delay
#gnuplot make_analyzer_recv_layer_delay
gnuplot make_analyzer_h_send_layer_delay
gnuplot make_analyzer_h_recv_layer_delay

scp -P 51111 analyzer_delay.png sonic@10.20.16.135:~/
scp -P 51111 analyzer_all_delay.png sonic@10.20.16.135:~/
#scp -P 51111 analyzer_layer_delay.png sonic@10.1.1.200:~/
scp -P 51111 analyzer_h_layer_delay.png sonic@10.20.16.135:~/
scp -P 51111 analyzer_hh_layer_delay.png sonic@10.20.16.135:~/
#scp -P 51111 analyzer_send_layer_delay.png sonic@10.1.1.200:~/
#scp -P 51111 analyzer_recv_layer_delay.png sonic@10.1.1.200:~/
scp -P 51111 analyzer_h_send_layer_delay.png sonic@10.20.16.135:~/
scp -P 51111 analyzer_h_recv_layer_delay.png sonic@10.20.16.135:~/
