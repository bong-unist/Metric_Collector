from collections import defaultdict

class ebpfCode:
	def __init__(self):
		self.func_name = ["sock_sendmsg", "tcp_sendmsg", "ip_local_out", "sock_recvmsg", "tcp_v4_rcv", "ip_local_deliver"]
		self.param_pos = defaultdict()
		self.func_type = defaultdict()
		self.evt_type = defaultdict()
	
	def __set_variable__(self):
		self.param_pos["sock_sendmsg"] = "struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);"
		self.param_pos["sock_recvmsg"] = "struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);"
		self.param_pos["tcp_sendmsg"] = "struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx); size_t size = (size_t)PT_REGS_PARM3(ctx);"
		self.param_pos["tcp_recvmsg"] = "struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx); size_t size = (size_t)PT_REGS_PARM3(ctx);"
		self.param_pos["tcp_v4_rcv"] = "struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);"
		self.param_pos["ip_local_out"] = "struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);"
		self.param_pos["ip_local_deliver"] = "struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);"
		self.param_pos["dev_queue_xmit"] = "struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);"

		self.func_type["sock_sendmsg"] = 0
		self.func_type["sock_recvmsg"] = 0
		self.func_type["tcp_sendmsg"] = 1
		self.func_type["tcp_recvmsg"] = 1
		self.func_type["tcp_v4_rcv"] = 2
		self.func_type["ip_local_out"] = 2
		self.func_type["ip_local_deliver"] = 2
		self.func_type["dev_queue_xmit"] = 2

		for idx, func_name in enumerate(self.func_name):
			self.evt_type[func_name] = str(idx)

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

            #define IPV4_TYPE 4
			#define TCP_TYPE 6
			#define CYCLE_CRI1 (4200000000)
			#define CYCLE_CRI2 (100000)
			#define CYCLE_CRI3 (1000000000)

			struct flow_info {
				u32 src_addr;
				u32 dst_addr;
				u16 src_port;
				u16 dst_port;
				u8 evt_type;
			};

			struct event_data {
				u32 src_addr, dst_addr;
				u16 src_port, dst_port;
				u64 data_len;
				u64 ts;
				u8 evt_type;
			};

		"""
	
	def __set_map__(self):
		return """
            BPF_RINGBUF_OUTPUT(event_ringbuf, (1 << 17));
			BPF_TABLE("hash", u8, u32, sampling_size, 1);
            BPF_HASH(h_pid, u32, struct flow_info);
			BPF_HASH(h_pid_t, u32, u64);
			BPF_HASH(h_data_len, struct flow_info, u64);
			BPF_HASH(h_sample_size, struct flow_info, u64);
			BPF_HASH(h_prev_seq, struct flow_info, u32);
		"""

	def __set_common_func__(self):
		return """
			static inline void network_header_read(void *network_header, u8 ip_header[20]) {
				bpf_probe_read_kernel(ip_header, 20, network_header);
			}

			static inline s32 tcp_header_to_header_length(void *transport_header) {
				u8 tcp_data_offset;
				u8 tcp_header_length;

				bpf_probe_read_kernel(&tcp_data_offset, sizeof(tcp_data_offset), transport_header + 12);
				tcp_header_length = ((tcp_data_offset >> 4) << 2);
				return tcp_header_length;
			}

			static inline void * sk_buff_to_network_header_low_layer(struct sk_buff *skb) {
				return skb->data;
			}

			static inline void * sk_buff_to_network_header(struct sk_buff *skb) {
				u16 network_header;

				bpf_probe_read_kernel(&network_header, sizeof(network_header), &(skb->network_header));
				return skb->head + skb->network_header;
			}

			static inline s32 network_header_to_data_len(void *network_header, u8 ip_header[20]) {
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

			static inline u64 set_data_len(struct flow_info flow_info, u32 data_len) {
                u64 *prev_data_len = h_data_len.lookup(&flow_info);
                u64 cur_data_len = data_len;

                if (prev_data_len) {
					cur_data_len = (cur_data_len + *prev_data_len);
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

            static inline void event_occur(struct flow_info flow_info, u64 data_len, u8 evt_type, u8 endian) {
                struct event_data *data = event_ringbuf.ringbuf_reserve(sizeof(struct event_data));
                if (data) {
                    data->src_addr = endian ? bpf_ntohl(flow_info.src_addr) : flow_info.src_addr;
                    data->dst_addr = endian ? bpf_ntohl(flow_info.dst_addr) : flow_info.dst_addr;
                    data->src_port = flow_info.src_port;
                    data->dst_port = flow_info.dst_port;
                    data->data_len = data_len;
                    data->ts = bpf_ktime_get_boot_ns();
                    data->evt_type = evt_type;
                    event_ringbuf.ringbuf_submit(data, 0);
                };
            }

			static inline void event_occur_sock(struct flow_info flow_info, u64 data_len, u8 evt_type, u8 endian, u64 ts) {
                struct event_data *data = event_ringbuf.ringbuf_reserve(sizeof(struct event_data));
                if (data) {
                    data->src_addr = endian ? bpf_ntohl(flow_info.src_addr) : flow_info.src_addr;
                    data->dst_addr = endian ? bpf_ntohl(flow_info.dst_addr) : flow_info.dst_addr;
                    data->src_port = flow_info.src_port;
                    data->dst_port = flow_info.dst_port;
                    data->data_len = data_len;
                    data->ts = ts;
                    data->evt_type = evt_type;
                    event_ringbuf.ringbuf_submit(data, 0);
                };
            }
	
	"""
	
	def __set_common_func_sock__(self):
		return """
			static inline struct flow_info make_flow_info_sock(struct sock *sk, u8 evt_type) {
				struct flow_info flow_info = {
					.src_addr = evt_type == 3 ? sk->sk_daddr : sk->sk_rcv_saddr,
					.dst_addr = evt_type == 3 ? sk->sk_rcv_saddr : sk->sk_daddr,
					.src_port = evt_type == 3 ? bpf_ntohs(sk->sk_dport) : (sk->sk_portpair >> 16),
					.dst_port = evt_type == 3 ? (sk->sk_portpair >> 16) : bpf_ntohs(sk->sk_dport),
					.evt_type = evt_type
				};
				return flow_info;
			}
            
            static inline u8 get_flow_info(u32 pid, struct flow_info *flow_info) {
                struct flow_info *stored_flow_info = h_pid.lookup(&pid);
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

			static inline u8 is_retrans(struct flow_info flow_info, u32 cur_seq, u32 *prev_seq) {
                u32 *prev_seq_ = h_prev_seq.lookup(&flow_info);

                if (prev_seq_) {
					*prev_seq = *prev_seq_;
					if (*prev_seq >= CYCLE_CRI1 && cur_seq <= CYCLE_CRI2) return 0;
					if (*prev_seq <= CYCLE_CRI3 && cur_seq >= CYCLE_CRI1) return 1;
                    if (cur_seq <= *prev_seq) return 1;
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
                        data_len_ = (UINT_MAX - (u64) prev_seq) + (u64) cur_seq + 1;
                    }
                    else data_len_ = (u64) cur_seq - (u64) prev_seq;
                }
				else data_len_ = data_len;
				
                return data_len_;
            }
		"""
	
	def __set_body_func_sock__(self):
		return """
            int _#function_name#(struct pt_regs *ctx) {
                #param_pos#
                struct sock *sk = sock->sk;
                u32 pid = bpf_get_current_pid_tgid();
				u64 ts = bpf_ktime_get_boot_ns();
                
                struct flow_info flow_info;
                flow_info = make_flow_info_sock(sk, #evt_type#);
                
                h_pid.update(&pid, &flow_info);
				h_pid_t.update(&pid, &ts);

                return 0;
            }
            
			int #function_name#(struct pt_regs *ctx) {
				#param_pos#
				struct sock *sk = sock->sk;
                u32 pid = bpf_get_current_pid_tgid();
				s32 data_len = PT_REGS_RC(ctx);
				u64 *ts;

				struct flow_info flow_info = {};
				u64 data_len_, zero = 0;

				if (data_len <= 0) return 0; 

				if (!get_flow_info(pid, &flow_info)) return 0;
				data_len_ = set_data_len(flow_info, (u32) data_len);

				ts = h_pid_t.lookup(&pid);
				if (!ts) return 0;
				
				if (is_event_occur(flow_info, data_len_)) {
					set_sampling_size(flow_info);
					event_occur_sock(flow_info, data_len_, #evt_type#, #BIG_ENDIAN#, *ts);
				}

				h_pid.delete(&pid);
				h_pid_t.delete(&pid);
				return 0;
			}
		"""
	
	def __set_body_func_tcp__(self):
		return """
			int #function_name#(struct pt_regs *ctx) {
				#param_pos#
				struct flow_info flow_info;

				u32 data_len;

				flow_info = make_flow_info_sock(sk, #evt_type#);
				data_len = set_data_len(flow_info, size);

				if (is_event_occur(flow_info, data_len)) {
					set_sampling_size(flow_info);
					event_occur(flow_info, data_len, #evt_type#, #BIG_ENDIAN#);
				}
				
				return 0;
			}
		"""
	
	def __set_body_func_ip__(self):
		return """
			int #function_name#(struct pt_regs *ctx) {
				#param_pos#
				u8 tcp_header[8];
				u8 ip_header[20];

				u32 data_len;
				u32 prev_seq, seq;

				struct flow_info flow_info;
				u64 data_len_, zero = 0;

				void *network_header = sk_buff_to_network_header(skb);
				void *headerp = network_header_to_transport_header(network_header, ip_header);	
				if (!headerp) return 0;
				headerp = skb->head + skb->transport_header;
				bpf_probe_read_kernel(&tcp_header, sizeof(tcp_header), headerp);

				seq = ((tcp_header[4] << 24) | (tcp_header[5] << 16) | (tcp_header[6] << 8) | tcp_header[7]);
				flow_info = make_flow_info_skb(ip_header, tcp_header, #evt_type#);
				if (is_retrans(flow_info, seq, &prev_seq)) return 0;

				data_len = network_header_to_data_len(network_header, ip_header);
				if (!data_len) data_len = network_header_to_data_len2(network_header, ip_header, bpf_htons(skb->len));
				data_len_ = set_data_len(flow_info, get_data_len(flow_info, seq, prev_seq, data_len));
				
				if (is_event_occur(flow_info, data_len_)) {
					set_sampling_size(flow_info);
					event_occur(flow_info, data_len_, #evt_type#, #LITTLE_ENDIAN#);
				}
				
				h_prev_seq.update(&flow_info, &seq);
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
				code += self.__set_body_func_sock__()
			elif self.func_type[func_name] == 1:
				code += self.__set_body_func_tcp__()
			else:
				code += self.__set_body_func_ip__()
			code = code.replace("#function_name#", "__" + func_name)
			code = code.replace("#param_pos#", self.param_pos[func_name])
			code = code.replace("#evt_type#", self.evt_type[func_name])
	
		code = code.replace("#BIG_ENDIAN#", "0")
		code = code.replace("#LITTLE_ENDIAN#", "1")
		return code



























