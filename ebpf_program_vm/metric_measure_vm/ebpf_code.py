from collections import defaultdict

class ebpfCode:
	def __init__(self):
		self.func_name = ["sock_sendmsg", "tcp_v4_send_check", "ip_finish_output2", "dev_queue_xmit", "sock_recvmsg", "tcp_v4_rcv", "ip_local_deliver", "netif_receive_skb", "kernel_sendpage", "tcp_sendpage", "__netif_receive_skb_core", "virtqueue_add_outbuf"]
		self.param_pos = defaultdict()
		self.func_type = defaultdict()
		self.evt_type = defaultdict()
	
	def __set_variable__(self):
		self.param_pos["sock_sendmsg"] = "struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx); struct sock *sk = sock->sk;"
		self.param_pos["kernel_sendpage"] = "struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx); struct sock *sk = sock->sk;"
		self.param_pos["tcp_sendmsg"] = "struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx); size_t size = (size_t)PT_REGS_PARM3(ctx);"
		self.param_pos["tcp_sendpage"] = "struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx); size_t size = (size_t)PT_REGS_PARM4(ctx);"
		self.param_pos["sock_recvmsg"] = "struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx); struct sock *sk = sock->sk;"
		self.param_pos["tcp_recvmsg"] = "struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx); size_t size = (size_t)PT_REGS_PARM3(ctx);"
		self.param_pos["__tcp_transmit_skb"] = "struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx); struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);"
		self.param_pos["tcp_v4_send_check"] = "struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx); struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);"
		self.param_pos["tcp_v4_rcv"] = "struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);"
		self.param_pos["ip_finish_output2"] = "struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);"
		self.param_pos["ip_local_out"] = "struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);"
		self.param_pos["dev_queue_xmit"] = "struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);"
		self.param_pos["virtqueue_add_outbuf"] = "struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM4(ctx);"
		self.param_pos["ip_local_deliver"] = "struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);"
		self.param_pos["netif_receive_skb"] = "struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);"
		self.param_pos["__netif_receive_skb_core"] = "struct sk_buff **pskb = (struct sk_buff **)PT_REGS_PARM1(ctx); struct sk_buff *skb = *pskb;"

		self.func_type["sock_sendmsg"] = 0
		self.func_type["kernel_sendpage"] = 0
		self.func_type["tcp_sendmsg"] = 0
		self.func_type["tcp_sendpage"] = 0
		self.func_type["sock_recvmsg"] = 1
		self.func_type["tcp_recvmsg"] = 1
		self.func_type["tcp_transmit_skb"] = 2
		self.func_type["tcp_v4_send_check"] = 2
		self.func_type["tcp_v4_rcv"] = 4
		self.func_type["ip_finish_output2"] = 4
		self.func_type["ip_local_out"] = 4
		self.func_type["dev_queue_xmit"] = 4
		self.func_type["virtqueue_add_outbuf"] = 4
		self.func_type["ip_local_deliver"] = 4
		self.func_type["netif_receive_skb"] = 4
		self.func_type["__netif_receive_skb_core"] = 4

		for idx, func_name in enumerate(self.func_name):
			self.evt_type[func_name] = str(idx)

		if self.evt_type.get("kernel_sendmsg") != None and self.evt_type.get("sock_sendmsg") != None:
			self.evt_type["kernel_sendpage"] = self.evt_type["sock_sendmsg"]
		if self.evt_type.get("tcp_sendpage") != None and self.evt_type.get("tcp_sendmsg") != None:
			self.evt_type["tcp_sendpage"] = self.evt_type["tcp_sendmsg"]
		if self.evt_type.get("__tcp_transmit_skb") != None and self.evt_type.get("tcp_v4_send_check") != None:
			self.evt_type["__tcp_transmit_skb"] = self.evt_type["tcp_v4_send_check"]
		if self.evt_type.get("__netif_receive_skb_core") != None and self.evt_type.get("netif_receive_skb") != None:
			self.evt_type["__netif_receive_skb_core"] = self.evt_type["netif_receive_skb"]
		if self.evt_type.get("virtqueue_add_outbuf") != None and self.evt_type.get("dev_queue_xmit") != None:
			self.evt_type["virtqueue_add_outbuf"] = self.evt_type["dev_queue_xmit"]

	def __set_header__(self):
		return """
			#include <linux/net.h>
			#include <linux/netdevice.h>
			#include <linux/sched.h>
			#include <net/dst.h>
			#include <net/sock.h>
			#include <uapi/linux/bpf.h>
			#include <uapi/linux/ptrace.h>
			#include <uapi/linux/uio.h>
			#include <net/tcp.h>

            #define IPV4_TYPE 4
			#define TCP_TYPE 6
			#define CYCLE_CRI1 (4200000000)
			#define CYCLE_CRI2 (100000)
			#define CYCLE_CRI3 (1000000000)
			#define TCP_SKB_CB(__skb)   ((struct tcp_skb_cb *)&((__skb)->cb[0]))

			struct pid_info {
				u32 pid;
				u32 tid;
				u8 evt_type;
			} __attribute__ ((__packed__));

			struct flow_info {
				u32 src_addr;
				u32 dst_addr;
				u16 src_port;
				u16 dst_port;
				u8 evt_type;
			};

			struct event_data {
				u64 start_seq, cur_seq;
				u64 data_len;
				u64 ts;
				u64 tid;
				u32 src_addr, dst_addr;
				u32 cpuid;
				u16 src_port, dst_port; 
				u8 evt_type;
				u8 is_retrans;
			} __attribute__ ((aligned(64)));

		"""
	
	def __set_map__(self):
		return """
            BPF_RINGBUF_OUTPUT(event_ringbuf, (1 << 17));
			BPF_TABLE("hash", u8, u32, sampling_size, 1);
			BPF_TABLE("hash", u16, u8, sampling_port, 10);
            BPF_HASH(h_pid, struct pid_info, struct flow_info);
			BPF_HASH(h_pid_ts, struct pid_info, u64);
			BPF_HASH(h_pid_seq, struct flow_info, u32);
			BPF_HASH(h_pid_data_len, struct flow_info, u32);
			BPF_HASH(h_data_len, struct flow_info, u64);
			BPF_HASH(h_sample_size, struct flow_info, u64);
			BPF_HASH(h_prev_seq, struct flow_info, u64);
			BPF_HASH(h_prev_ts, struct flow_info, u64);
			BPF_HASH(h_prev_reseq, struct flow_info, u64);
			BPF_HASH(h_prev_rets, struct flow_info, u64);
			BPF_HASH(h_cycle, struct flow_info, u64);

			BPF_HASH(h_pid_start_data_len, struct pid_info, u64);
			BPF_HASH(h_pid_data_len_, struct pid_info, u64);

			BPF_HASH(h_start_seq, struct flow_info, u64);
			BPF_HASH(h_cur_seq, struct flow_info, u64);
		"""

	def __set_common_func__(self):
		return """
			static inline void network_header_read(void *network_header, u8 ip_header[20]) {
				bpf_probe_read_kernel(ip_header, 20, network_header);
			}

			static inline u8 tcp_header_to_header_length(void *transport_header) {
				u8 tcp_data_offset;
				u8 tcp_header_length;

				bpf_probe_read_kernel(&tcp_data_offset, sizeof(tcp_data_offset), transport_header + 12);
				tcp_header_length = ((tcp_data_offset >> 4) << 2);
				return tcp_header_length;
			}

			static inline void * sk_buff_to_network_header_low_layer(struct sk_buff *skb) {
				return skb->data;
			}

			static inline void * sk_buff_to_network_header(struct sk_buff *skb, u8 parsing_type) {
				u16 network_header;
				u16 source = skb->data - skb->head;

				if (parsing_type) {
					bpf_probe_read_kernel(&network_header, sizeof(network_header), &(source));
					return skb->head + (skb->data - skb->head);
				}
				else {
					bpf_probe_read_kernel(&network_header, sizeof(network_header), &(skb->network_header));
					return skb->head + skb->network_header;
				}
			}

			static inline u32 network_header_to_data_len(void *network_header, u8 ip_header[20]) {
				void *transport_header;
				s32 ip_data_len;
				u8 ihl;

				ihl = ((ip_header[0] & 15) << 2);
				ip_data_len = ((ip_header[2] << 8) | (ip_header[3]));
				transport_header = network_header + ihl;
				
				if (!ip_data_len) return 0;
				return ip_data_len - ihl - tcp_header_to_header_length(transport_header);
			}

			static inline u32 network_header_to_data_len2(void *network_header, u8 ip_header[20], u32 ip_data_len) {
                void *transport_header;
                u8 ihl;

                ihl = ((ip_header[0] & 15) << 2);
                transport_header = network_header + ihl;

                return ip_data_len - ihl - tcp_header_to_header_length(transport_header);
            }

			static inline void * network_header_to_transport_header(void *network_header, u8 ip_header[20]) {
				u8 ihl = 0;
				network_header_read(network_header, ip_header);
				if ((ip_header[0] >> 4) != IPV4_TYPE)
					return NULL;
				if (ip_header[9] != TCP_TYPE)
					return NULL;

				ihl = ((ip_header[0] & 15) << 2);
				return network_header + ihl;
			}

			static inline u64 set_data_len(struct flow_info flow_info, u64 *start_data_len, u64 data_len) {
                u64 *prev_data_len = h_data_len.lookup(&flow_info);
                u64 cur_data_len = data_len;

                if (prev_data_len) {
					cur_data_len = (cur_data_len + *prev_data_len);
					*start_data_len = *prev_data_len;
                }

                h_data_len.update(&flow_info, &cur_data_len);
                return cur_data_len;
            }

			static inline u64 get_sampling_size(struct flow_info flow_info) {
				u8 key = 1;
                u32 *ssize_ = sampling_size.lookup(&key);
                u32 ssize = (ssize_ ? *ssize_ : 0);

                u64 zero = 0;
                u64 *size = h_sample_size.lookup_or_try_init(&flow_info, &zero);
                if (size) return *size;
                return ssize;
			}

			static inline void set_sampling_size(struct flow_info flow_info) {
                u8 key = 1;
                u32 *ssize_ = sampling_size.lookup(&key);
                u64 ssize = (ssize_ ? *ssize_ : 0);

                u64 zero = 0;
                u64 *size_ = h_sample_size.lookup_or_try_init(&flow_info, &zero);

                ssize = ssize + (size_ ? *size_ : 0);
                h_sample_size.update(&flow_info, &ssize);
            }

			static inline u8 is_event_occur(struct flow_info flow_info, u64 data_len) {
                u64 sampling_size = get_sampling_size(flow_info);
                return data_len >= sampling_size;
            }
	
			static inline void event_occur(struct pt_regs *ctx, struct flow_info flow_info, u64 data_len, u8 evt_type, u8 endian, u64 ts, u64 start_seq, u64 cur_seq, u8 is_retrans) {
                struct event_data *data = event_ringbuf.ringbuf_reserve(sizeof(struct event_data));
				struct task_struct *task = (struct task_struct *) bpf_get_current_task();
                if (data) {
                    data->src_addr = endian ? bpf_ntohl(flow_info.src_addr) : flow_info.src_addr;
                    data->dst_addr = endian ? bpf_ntohl(flow_info.dst_addr) : flow_info.dst_addr;
                    data->src_port = flow_info.src_port;
                    data->dst_port = flow_info.dst_port;
                    data->data_len = data_len;
                    data->ts = ts;
                    data->evt_type = evt_type;
					data->tid = bpf_get_current_pid_tgid();
					data->start_seq = start_seq;
					data->cur_seq = cur_seq;
					data->is_retrans = is_retrans;
					data->cpuid = task->cpu;
                    event_ringbuf.ringbuf_submit(data, BPF_RB_FORCE_WAKEUP);
                }
            }

			static inline u8 check_recv_socket(struct flow_info flow_info, u64 data_len) {
				flow_info.src_addr = bpf_ntohl(flow_info.src_addr);
				flow_info.dst_addr = bpf_ntohl(flow_info.dst_addr);
				flow_info.evt_type = 4;
				u64 *socket_data_len;

				socket_data_len = h_data_len.lookup(&flow_info);
				if (!socket_data_len) return 0;
				if (*socket_data_len >= data_len) return 1;
				return 0;
			}

			static inline u8 check_port(u16 port) {
				u8 *ret_, ret = 0;

				ret_ = sampling_port.lookup(&port);
				if (ret_) {
					ret = *ret_;
				}

				return ret;
			}
	
	"""
	
	def __set_common_func_sock__(self):
		return """
			static inline struct flow_info make_flow_info_sock(struct sock *sk, u8 evt_type) {
				struct flow_info flow_info = {
					.src_addr = evt_type == 4 ? sk->sk_daddr : sk->sk_rcv_saddr,
					.dst_addr = evt_type == 4 ? sk->sk_rcv_saddr : sk->sk_daddr,
					.src_port = evt_type == 4 ? bpf_ntohs(sk->sk_dport) : (sk->sk_portpair >> 16),
					.dst_port = evt_type == 4 ? (sk->sk_portpair >> 16) : bpf_ntohs(sk->sk_dport),
					.evt_type = evt_type
				};
				return flow_info;
			}
            
            static inline u8 get_flow_info(struct pid_info pid_info, struct flow_info *flow_info) {
                struct flow_info *stored_flow_info = h_pid.lookup(&pid_info);
                if (stored_flow_info) {
                    flow_info->src_addr = stored_flow_info->src_addr;
                    flow_info->dst_addr = stored_flow_info->dst_addr;
                    flow_info->src_port = stored_flow_info->src_port;
                    flow_info->dst_port = stored_flow_info->dst_port;
                    flow_info->evt_type = stored_flow_info->evt_type;
                    return 1;
                }
                return 0;
            }
		"""

	def __set_common_func_ip__(self):
		return """
			static inline struct flow_info make_flow_info_skb(u8 ip_header[20], u8 tcp_header[8], u8 evt_type) {
				u32 src_addr, dst_addr;
				u16 src_port, dst_port;
				struct flow_info flow_info = {};

				struct task_struct *task = (struct task_struct *) bpf_get_current_task();

				src_addr = ((ip_header[12] << 24) | (ip_header[13] << 16) | (ip_header[14] << 8) | ip_header[15]);
				dst_addr = ((ip_header[16] << 24) | (ip_header[17] << 16) | (ip_header[18] << 8) | ip_header[19]);
				src_port = ((tcp_header[0] << 8) | tcp_header[1]);
				dst_port = ((tcp_header[2] << 8) | tcp_header[3]);

				flow_info.src_addr = src_addr;
				flow_info.dst_addr = dst_addr;
				flow_info.src_port = src_port;
				flow_info.dst_port = dst_port;
				flow_info.evt_type = evt_type;

				return flow_info;
			}

			static inline u8 is_retrans(struct flow_info flow_info, u32 cur_seq, u32 *prev_seq, u64 ts) {
                u64 *prev_seq_ = h_prev_seq.lookup(&flow_info);
				u64 *prev_ts = h_prev_ts.lookup(&flow_info);
				u64 BIGNUM = (1 << 30);
				
				u8 flag = (prev_ts ? (ts - *prev_ts) < 10000000 ? 0 : 1 : 0);

                if (prev_seq_) {
					*prev_seq = *prev_seq_;
					if (*prev_seq >= cur_seq && *prev_seq - cur_seq < BIGNUM) return (flag ? 1 : 2);
					else if (*prev_seq < cur_seq && cur_seq - *prev_seq > BIGNUM) return (flag ? 1 : 2);
                }
				else {
					*prev_seq = 0;
				}

                return 0;
            }

			static inline u64 get_data_len(struct flow_info flow_info, u32 cur_seq, u32 prev_seq, u32 data_len) {
				u64 data_len_;

                if (prev_seq) {
                    if (prev_seq > cur_seq) {
                        data_len_ = (UINT_MAX - (u64) prev_seq) + (u64) cur_seq;
                    }
                    else data_len_ = (u64) cur_seq - (u64) prev_seq;

					if (!data_len && data_len_ == 1) data_len_ = data_len_ - 1;
                }
				else data_len_ = data_len;

                return data_len_;
            }

			static inline u8 is_retrans2(struct flow_info flow_info, u64 cur_seq, u64 *prev_seq, u64 ts) {
                u64 *prev_seq_ = h_prev_seq.lookup(&flow_info);
				u64 *prev_ts = h_prev_ts.lookup(&flow_info);
                u64 BIGNUM = (1 << 30);

				u8 flag = 0;
				if (prev_ts) {
					if (ts - *prev_ts > 10000000) flag = 1;
				}

                if (prev_seq_) {
                    *prev_seq = *prev_seq_;
                    if (*prev_seq >= cur_seq && *prev_seq - cur_seq < BIGNUM) {
						if (flag) {
							u64 *prev_reseq = h_prev_reseq.lookup(&flow_info);
							u64 *prev_rets = h_prev_rets.lookup(&flow_info);
							if (prev_reseq && prev_rets && *prev_reseq == cur_seq && (ts - *prev_rets) < 10000000) return 3;
							return 1;
						}
						else return 2;
					}
                    else if (*prev_seq < cur_seq && cur_seq - *prev_seq > BIGNUM) {
						if (flag) {
							u64 *prev_reseq = h_prev_reseq.lookup(&flow_info);
							u64 *prev_rets = h_prev_rets.lookup(&flow_info);
							if (prev_reseq && prev_rets && *prev_reseq == cur_seq && (ts - *prev_rets) < 10000000) return 3;
							return 1;
						}
						else return 2;
					}
                }
                else {
                    *prev_seq = 0;
                }

                return 0;
            }

			static inline u64 get_data_len2(struct flow_info flow_info, u64 cur_seq, u64 prev_seq) {
				u64 data_len_ = 0;
				u64 *start_seq = h_start_seq.lookup(&flow_info);
				if (!start_seq || !prev_seq) return 0;
				u64 *cycle = h_cycle.lookup(&flow_info);
				u64 cycle_ = (cycle ? *cycle : 0);

				if (prev_seq > cur_seq) {
					cycle_++;
					data_len_ = (cur_seq + cycle_ * UINT_MAX) - *start_seq;
					h_cycle.update(&flow_info, &cycle_);
				}
				else {
					data_len_ = (cur_seq + cycle_ * UINT_MAX) - *start_seq;
				}

				return data_len_;
			}
		"""

	def __set_body_func_sock_enter__(self):
		return """
			int #function_name#(struct pt_regs *ctx) {
                #param_pos#
                u32 pid = bpf_get_current_pid_tgid() >> 32;
                u32 tid = bpf_get_current_pid_tgid();
                u64 ts = bpf_ktime_get_boot_ns(), zero = 0;
                u8 evt_type = #evt_type#;

                struct flow_info flow_info = {};
                if (#evt_type# >= 10) {
                    flow_info = make_flow_info_sock(sk, (evt_type == 10 ? 0 : 1));
                }
                else {
                    flow_info = make_flow_info_sock(sk, evt_type);
                }

                struct pid_info pid_info = {};
                pid_info.pid = pid;
                pid_info.tid = tid;
                pid_info.evt_type = evt_type;

                h_pid.update(&pid_info, &flow_info);
				h_pid_ts.update(&pid_info, &ts);

                return 0;
            }

            int _#function_name#(struct pt_regs *ctx) {
                #param_pos#
                u32 pid = bpf_get_current_pid_tgid() >> 32;
                u32 tid = bpf_get_current_pid_tgid();
                s32 data_len = PT_REGS_RC(ctx);
				u64 cur_ts = bpf_ktime_get_boot_ns(), *ts;
                u8 evt_type = #evt_type#;
				
                struct flow_info flow_info = {};
                struct pid_info pid_info = {};
                pid_info.pid = pid;
                pid_info.tid = tid;
                pid_info.evt_type = evt_type;

                u64 start_data_len = 0, data_len_, zero = 0;

                if (data_len <= 0) return 0;

                if (!get_flow_info(pid_info, &flow_info)) return 0;
				ts = h_pid_ts.lookup(&pid_info);
				if (!ts) return 0;
				
                data_len_ = set_data_len(flow_info, &start_data_len, (u64) data_len);

                if (is_event_occur(flow_info, data_len_) && (check_port(flow_info.src_port) || check_port(flow_info.dst_port))) {
                    set_sampling_size(flow_info);
                    event_occur(ctx, flow_info, data_len_, flow_info.evt_type, #BIG_ENDIAN#, *ts, 0, 0, 0);
                }

                h_pid.delete(&pid_info);
				h_pid_ts.delete(&pid_info);
                return 0;
            }
		"""
	
	def __set_body_func_sock_exit__(self):
		return """
            int #function_name#(struct pt_regs *ctx) {
                #param_pos#
                u32 pid = bpf_get_current_pid_tgid() >> 32;
				u32 tid = bpf_get_current_pid_tgid();
				u64 ts = bpf_ktime_get_boot_ns(), zero = 0;
                u8 evt_type = #evt_type#;
				
                struct flow_info flow_info = {};
				if (#evt_type# >= 10) {
					flow_info = make_flow_info_sock(sk, (evt_type == 10 ? 0 : 1));
				}
				else {
					flow_info = make_flow_info_sock(sk, evt_type);
				}
				
				struct pid_info pid_info = {};
				pid_info.pid = pid;
				pid_info.tid = tid;
				pid_info.evt_type = evt_type;

                h_pid.update(&pid_info, &flow_info);
				h_pid_ts.update(&pid_info, &ts);

                return 0;
            }
            
			int _#function_name#(struct pt_regs *ctx) {
				#param_pos#
                u32 pid = bpf_get_current_pid_tgid() >> 32;
				u32 tid = bpf_get_current_pid_tgid();
				s32 data_len = PT_REGS_RC(ctx);
				u64 ts = bpf_ktime_get_boot_ns(), *entry_ts;
				u8 evt_type = #evt_type#;
				
				struct flow_info flow_info = {};
				struct pid_info pid_info = {};
				pid_info.pid = pid;
				pid_info.tid = tid;
				pid_info.evt_type = evt_type;

				u64 start_data_len = 0, data_len_, zero = 0;

				if (data_len <= 0) return 0; 

				if (!get_flow_info(pid_info, &flow_info)) return 0;
				if (!(entry_ts = h_pid_ts.lookup(&pid_info))) return 0; 
				data_len_ = set_data_len(flow_info, &start_data_len, (u64) data_len);
				
				if (is_event_occur(flow_info, data_len_) && (check_port(flow_info.src_port) || check_port(flow_info.dst_port))) {
					set_sampling_size(flow_info);
					event_occur(ctx, flow_info, data_len_, flow_info.evt_type, #BIG_ENDIAN#, ts, 0, 0, 0);
				}

				h_pid.delete(&pid_info);
				h_pid_ts.delete(&pid_info);
				return 0;
			}
		"""
	
	def __set_body_func_tcp_enter__(self):
		return """
			int #function_name#(struct pt_regs *ctx) {
				#param_pos#
				struct tcphdr *th = (struct tcphdr *) skb->data;
                u32 seq = th->seq; seq = ntohl(seq);
				u32 data_len = skb->len - 32; 
				u64 prev_seq;
				u64 data_len_ = 1111;
				u64 ts = bpf_ktime_get_boot_ns();
                u8 evt_type = #evt_type#;
				u8 is_retrans = 0;
				
				u32 pid = bpf_get_current_pid_tgid() >> 32;
				u32 tid = bpf_get_current_pid_tgid();

				if (!seq || !data_len) return 0;

				u64 start_seq = seq, *start_seq_;
				u64 cur_seq = seq + data_len;

                struct flow_info flow_info = {};
                flow_info = make_flow_info_sock(sk, evt_type);
                flow_info.src_addr = bpf_ntohl(flow_info.src_addr);
                flow_info.dst_addr = bpf_ntohl(flow_info.dst_addr);

				if (!(start_seq_ = h_start_seq.lookup(&flow_info))) h_start_seq.update(&flow_info, &start_seq);
				is_retrans = is_retrans2(flow_info, cur_seq, &prev_seq, ts);
			
				if (!is_retrans)
					data_len_ = get_data_len2(flow_info, cur_seq, prev_seq);
				else if (is_retrans == 1) data_len_ = 0;
				else if (is_retrans == 3) return 0;

 				if (is_event_occur(flow_info, data_len_) && (check_port(flow_info.src_port) || check_port(flow_info.dst_port))) {
                    set_sampling_size(flow_info);
                    event_occur(ctx, flow_info, data_len_, evt_type, #LITTLE_ENDIAN#, ts, (!start_seq_ ? start_seq : *start_seq_), cur_seq, is_retrans);
                }

				if (!is_retrans) {
					h_prev_seq.update(&flow_info, &cur_seq);
					h_prev_ts.update(&flow_info, &ts);
				}
				else if (is_retrans == 1) {
					h_prev_reseq.update(&flow_info, &cur_seq);
					h_prev_rets.update(&flow_info, &ts);
				}

				return 0;
			}
		"""

	def __set_body_func_tcp_exit__(self):
		return """
			int #function_name#(struct pt_regs *ctx) {
				#param_pos#
				u32 pid = bpf_get_current_pid_tgid() >> 32;
				u32 tid = bpf_get_current_pid_tgid();
				
				struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
				u32 seq = tcb->seq, prev_seq;
				u32 data_len = skb->len - 32;
				u8 evt_type = #evt_type#;

				struct flow_info flow_info = {};
				flow_info = make_flow_info_sock(sk, evt_type);
				flow_info.src_addr = bpf_ntohl(flow_info.src_addr);
				flow_info.dst_addr = bpf_ntohl(flow_info.dst_addr);
				
				struct pid_info pid_info = {};
				pid_info.pid = pid;
				pid_info.tid = tid;
				pid_info.evt_type = evt_type;

				h_pid.update(&pid_info, &flow_info);
				h_pid_seq.update(&flow_info, &seq);

				return 0;
			}
				
			int _#function_name#(struct pt_regs *ctx) {
				#param_pos#
				u32 pid = bpf_get_current_pid_tgid() >> 32;
                u32 tid = bpf_get_current_pid_tgid();
				
				u32 *seq, prev_seq;
				u32 data_len = 0; u64 data_len_;
				u8 evt_type = #evt_type#;
				u64 start_data_len = 0;
				u64 cur_send_bytes;
				u64 ts = bpf_ktime_get_boot_ns();

				struct flow_info flow_info = {};
				struct pid_info pid_info = {};
				pid_info.pid = pid;
				pid_info.tid = tid;
				pid_info.evt_type = evt_type;

				if (!get_flow_info(pid_info, &flow_info)) return 0;

				seq = h_pid_seq.lookup(&flow_info);
				if (!seq) return 0;

				if (is_retrans(flow_info, *seq, &prev_seq)) return 0;

				cur_send_bytes = get_data_len(flow_info, *seq, prev_seq, data_len);
				if (!cur_send_bytes) {
					h_pid.delete(&pid_info);
					h_prev_seq.update(&flow_info, seq);
					return 0;
				}
				data_len_ = set_data_len(flow_info, &start_data_len, cur_send_bytes);
				
				if (is_event_occur(flow_info, data_len_) && (check_port(flow_info.src_port) || check_port(flow_info.dst_port)) && data_len_) {
					set_sampling_size(flow_info);
					event_occur(ctx, flow_info, start_data_len, data_len_, evt_type, #LITTLE_ENDIAN#, ts, 0);
				}
			
				h_pid.delete(&pid_info);
				h_prev_seq.update(&flow_info, seq);
				return 0;
			}
		"""
	
	def __set_body_func_ip_enter__(self):
		return """
			int #function_name#(struct pt_regs *ctx) {
				#param_pos#
				u8 tcp_header[8];
                u8 ip_header[20];

                u32 data_len;
                u32 seq;
				u64 prev_seq;
                u8 evt_type = #evt_type#;
				u8 parsing_type = #parsing_type#;
				u8 is_retrans = 0;

                struct flow_info flow_info = {};
                u64 start_data_len = 0, data_len_ = 1111, zero = 0;
				u64 cur_send_bytes;
				u64 ts = bpf_ktime_get_boot_ns();
				
				u32 pid = bpf_get_current_pid_tgid() >> 32;
                u32 tid = bpf_get_current_pid_tgid();

                void *network_header = sk_buff_to_network_header(skb, parsing_type);
                void *headerp = network_header_to_transport_header(network_header, ip_header);
                if (!headerp) return 0;
				if (parsing_type) 
					headerp = skb->head + ((skb->data - skb->head) + ((ip_header[0] & 15) << 2));
				else
					headerp = skb->head + skb->transport_header;
                bpf_probe_read_kernel(&tcp_header, sizeof(tcp_header), headerp);

                seq = ((tcp_header[4] << 24) | (tcp_header[5] << 16) | (tcp_header[6] << 8) | tcp_header[7]);
                flow_info = make_flow_info_skb(ip_header, tcp_header, evt_type);

				if (!(check_port(flow_info.src_port) || check_port(flow_info.dst_port))) {
					headerp = skb->head + skb->transport_header + ((ip_header[0] & 15) << 2);
					bpf_probe_read_kernel(&tcp_header, sizeof(tcp_header), headerp);
					seq = ((tcp_header[4] << 24) | (tcp_header[5] << 16) | (tcp_header[6] << 8) | tcp_header[7]);
					flow_info = make_flow_info_skb(ip_header, tcp_header, evt_type);
				}

                data_len = network_header_to_data_len(network_header, ip_header);

				if (!data_len) return 0;
				if (evt_type == 7 && !seq) return 0;

				u64 start_seq = seq, *start_seq_;
				u64 cur_seq = seq + data_len;

				if (!(start_seq_ = h_start_seq.lookup(&flow_info))) h_start_seq.update(&flow_info, &start_seq);
				is_retrans = is_retrans2(flow_info, cur_seq, &prev_seq, ts);

				if (!is_retrans)
					data_len_ = get_data_len2(flow_info, cur_seq, prev_seq);
				else if (is_retrans == 1) data_len_ = 0;
				else if (is_retrans == 3) return 0;
				
				if (is_event_occur(flow_info, data_len_) && (check_port(flow_info.src_port) || check_port(flow_info.dst_port))) {
                    set_sampling_size(flow_info);
                    event_occur(ctx, flow_info, data_len_, evt_type, #LITTLE_ENDIAN#, ts, (!start_seq_ ? start_seq : *start_seq_), cur_seq, is_retrans);
                }

				if (!is_retrans) {
					h_prev_seq.update(&flow_info, &cur_seq);
					h_prev_ts.update(&flow_info, &ts);
				}
				else if (is_retrans == 1) {
					h_prev_reseq.update(&flow_info, &cur_seq);
					h_prev_rets.update(&flow_info, &ts);
				}
				
				return 0;
			}
		"""
	
	def __set_body_func_ip_exit__(self):
		return """
			int #function_name#(struct pt_regs *ctx) {
				#param_pos#
				u32 pid = bpf_get_current_pid_tgid() >> 32;
				u32 tid = bpf_get_current_pid_tgid();
				
				u8 tcp_header[8];
				u8 ip_header[20];

				u32 data_len;
				u32 seq;
				u8 evt_type = #evt_type#;
				u8 parsing_type = #parsing_type#;

				struct flow_info flow_info = {};
				u64 data_len_, zero = 0;

				void *network_header = sk_buff_to_network_header(skb, parsing_type);
				void *headerp = network_header_to_transport_header(network_header, ip_header);	
				if (!headerp) return 0;
				headerp = skb->head + skb->transport_header;
				bpf_probe_read_kernel(&tcp_header, sizeof(tcp_header), headerp);

				seq = ((tcp_header[4] << 24) | (tcp_header[5] << 16) | (tcp_header[6] << 8) | tcp_header[7]);
				flow_info = make_flow_info_skb(ip_header, tcp_header, evt_type);
				data_len = network_header_to_data_len(network_header, ip_header);

				struct pid_info pid_info = {};
				pid_info.pid = pid;
				pid_info.tid = tid;
				pid_info.evt_type = evt_type;

                h_pid.update(&pid_info, &flow_info);
                h_pid_seq.update(&flow_info, &seq);
                h_pid_data_len.update(&flow_info, &data_len);

				return 0;
			}
			
			int _#function_name#(struct pt_regs *ctx) {
				#param_pos#
				u32 pid = bpf_get_current_pid_tgid() >> 32;
				u32 tid = bpf_get_current_pid_tgid();
				u8 evt_type = #evt_type#;

				struct flow_info flow_info = {};
				struct pid_info pid_info = {};
				pid_info.pid = pid;
				pid_info.tid = tid;
				pid_info.evt_type = evt_type;

				u32 *seq, prev_seq;
				u32 *data_len; u64 data_len_;
				u64 start_data_len = 0;
				u64 cur_send_bytes;

				if (!get_flow_info(pid_info, &flow_info)) return 0;

				seq = h_pid_seq.lookup(&flow_info);
				if (!seq) return 0;
		
				data_len = h_pid_data_len.lookup(&flow_info);
				if (!data_len) return 0;

				if (is_retrans(flow_info, *seq, &prev_seq)) return 0;

				cur_send_bytes = get_data_len(flow_info, *seq, prev_seq, *data_len);
				if (!cur_send_bytes) {
					h_prev_seq.update(&flow_info, seq);
					return 0;
				}
				data_len_ = set_data_len(flow_info, &start_data_len, cur_send_bytes);
				
				if (is_event_occur(flow_info, data_len_) && (check_port(flow_info.src_port) || check_port(flow_info.dst_port)) && data_len_) {
					set_sampling_size(flow_info);
					event_occur(ctx, flow_info, start_data_len, data_len_, evt_type, #LITTLE_ENDIAN#, bpf_ktime_get_boot_ns(), 0);
				}
				
				h_prev_seq.update(&flow_info, seq);
				return 0;
			}
		"""

	def __main__(self):
		self.__set_variable__()
		code = self.__set_header__()
		code += self.__set_map__()
		code += self.__set_common_func__()
		code += self.__set_common_func_sock__()
		code += self.__set_common_func_ip__()

		for func_name in self.func_name:
			if self.func_type[func_name] == 0:
				code += self.__set_body_func_sock_enter__()
			elif self.func_type[func_name] == 1:
				code += self.__set_body_func_sock_exit__()
			elif self.func_type[func_name] == 2:
				code += self.__set_body_func_tcp_enter__()
			elif self.func_type[func_name] == 3:
				code += self.__set_body_func_tcp_exit__()
			elif self.func_type[func_name] == 4:
				code += self.__set_body_func_ip_enter__()
			elif self.func_type[func_name] == 5:	
				code += self.__set_body_func_ip_exit__()
			elif self.func_type[func_name] == 6:
				code += self.__set_body_func_tcp_mid__()

			code = code.replace("#function_name#", "___" + func_name)
			code = code.replace("#param_pos#", self.param_pos[func_name])
			if func_name.find("kernel_sendpage") != -1:
				code = code.replace("#evt_type#", "10")
			elif func_name.find("tcp_sendpage") != -1:
				code = code.replace("#evt_type#", "11")
			else:
				code = code.replace("#evt_type#", self.evt_type[func_name])

			if func_name.find("__netif_receive_skb_core") != -1:
				code = code.replace("#parsing_type#", "1")
			else:
				code = code.replace("#parsing_type#", "0")

		code = code.replace("#BIG_ENDIAN#", "0")
		code = code.replace("#LITTLE_ENDIAN#", "1")
		return code
