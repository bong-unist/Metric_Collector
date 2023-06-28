from collections import defaultdict

class ebpfCode:
	def __init__(self):
		self.func_name = ["virtio_dev_tx_split", "virtio_dev_tx_packed", "virtio_dev_rx_split", "virtio_dev_rx_packed", "mlx5_rx_burst_vec", "mlx5_tx_burst_none_empw"]
		self.mbuf_pos = defaultdict()
		self.pkt_cnt_pos = defaultdict()
		self.evt_type = defaultdict()

	def __set_variable__(self):
		self.mbuf_pos["virtio_dev_tx_split"] = "PT_REGS_PARM4(ctx)"
		self.mbuf_pos["virtio_dev_tx_packed"] = "PT_REGS_PARM4(ctx)"
		self.mbuf_pos["virtio_dev_rx_split"] = "PT_REGS_PARM3(ctx)"
		self.mbuf_pos["virtio_dev_rx_packed"] = "PT_REGS_PARM3(ctx)"
		self.mbuf_pos["mlx5_rx_burst_vec"] = "PT_REGS_PARM2(ctx)"
		self.mbuf_pos["mlx5_tx_burst_none_empw"] = "PT_REGS_PARM2(ctx)"

		self.pkt_cnt_pos["virtio_dev_tx_split"] = "PT_REGS_PARM5(ctx)"
		self.pkt_cnt_pos["virtio_dev_tx_packed"] = "PT_REGS_PARM5(ctx)"
		self.pkt_cnt_pos["virtio_dev_rx_split"] = "PT_REGS_PARM4(ctx)"
		self.pkt_cnt_pos["virtio_dev_rx_packed"] = "PT_REGS_PARM4(ctx)"
		self.pkt_cnt_pos["mlx5_rx_burst_vec"] = "PT_REGS_PARM5(ctx)"
		self.pkt_cnt_pos["mlx5_tx_burst_none_empw"] = "PT_REGS_PARM3(ctx)"

		for idx, func_name in enumerate(self.func_name):
			self.evt_type[func_name] = str(idx)

	def __set_header__(self):
		return """
			#include <linux/sched.h>
			#include <uapi/linux/ptrace.h>
			#include <uapi/linux/bpf.h>
			#include "ebpf_program_host/metric_measure/include/mbuf.h"
			#include "ebpf_program_host/metric_measure/include/packet.h"

			#define ETHER_TYPE (8)
			#define IPV4_TYPE (4)
			#define TCP_TYPE (6)
			#define CYCLE_CRI1 (4200000000)
            #define CYCLE_CRI2 (100000)
			#define CYCLE_CRI3 (1000000000)
			#define PACKET_PARSE (32)
			#define NUM_EVENT (10)
			
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
			BPF_HASH(h_prev_seq, struct flow_info, u32);
			BPF_HASH(h_data_len, struct flow_info, u64);
			BPF_HASH(h_sample_size, struct flow_info, u64);
			BPF_TABLE("hash", u8, u32, sampling_size, 1);
		"""
	
	def __set_common_func__(self):
		return """
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

			static inline u64 get_data_len(struct rte_ipv4_hdr iphdr, struct rte_tcp_hdr tcphdr, struct flow_info flow_info, u32 cur_seq, u32 prev_seq) {
				u64 data_len;

				if (prev_seq) { 
					if (prev_seq > cur_seq) {
						data_len = (UINT_MAX - (u64) prev_seq) + (u64) cur_seq + 1;
					}
					else data_len = (u64) cur_seq - (u64) prev_seq;
				}
				else {
					data_len = bpf_ntohs(iphdr.total_length) - ((tcphdr.data_off >> 4) << 2) - (iphdr.ihl << 2);
				}
				return data_len;
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

			static inline struct flow_info make_flow_info(struct rte_ipv4_hdr iphdr, struct rte_tcp_hdr tcphdr, u8 evt_type) {
				struct flow_info flow_info = {
					.src_addr = iphdr.src_addr,
					.dst_addr = iphdr.dst_addr,
					.src_port = tcphdr.src_port,
					.dst_port = tcphdr.dst_port,
					.evt_type = evt_type
				};
				return flow_info;
			}

			static inline u8 is_event_occur(struct flow_info flow_info, u64 data_len) {
				u64 sampling_size = get_sampling_size(flow_info);
				return data_len >= sampling_size;
			}

			static inline void event_occur(struct flow_info flow_info, u64 data_len, u8 evt_type) {
				struct event_data *data = event_ringbuf.ringbuf_reserve(sizeof(struct event_data));
				if (data) {
					data->src_addr = flow_info.src_addr;
					data->dst_addr = flow_info.dst_addr;
					data->src_port = bpf_ntohs(flow_info.src_port);
					data->dst_port = bpf_ntohs(flow_info.dst_port);
					data->data_len = data_len;
					data->ts = bpf_ktime_get_boot_ns();
					data->evt_type = evt_type;
					event_ringbuf.ringbuf_submit(data, 0);
				};
			}
		"""

	def __set_body_func__(self):
		return """
			int #function_name#(struct pt_regs *ctx) {
				struct rte_mbuf **pkts = (struct rte_mbuf**)#mbuf_pos#;
				struct rte_ether_hdr ethhdr;
				struct rte_ipv4_hdr iphdr;
				struct rte_tcp_hdr tcphdr;
				struct rte_mbuf *mbuf;
				struct flow_info flow_info;
				
				char *ether_hdr;
				s32 pkt_cnt = #pkt_cnt_pos#, seq;
				u64 data_len, zero = 0;
				u32 prev_seq;
				s16 i;
	
				for (i = 0; i < PACKET_PARSE; i++) {
					if (pkt_cnt && i >= pkt_cnt) break;

					mbuf = pkts[i];
					if (!mbuf) break;

					ether_hdr = mbuf->buf_addr + mbuf->data_off;
					bpf_probe_read(&ethhdr, sizeof(ethhdr), ether_hdr);
					if (ethhdr.ether_type != ETHER_TYPE) continue;

					bpf_probe_read(&iphdr, sizeof(iphdr), ether_hdr + sizeof(ethhdr));
					if ((iphdr.version_ihl >> 4) != IPV4_TYPE) continue;
					if (iphdr.next_proto_id != TCP_TYPE) continue;

					bpf_probe_read(&tcphdr, sizeof(tcphdr), ether_hdr + sizeof(ethhdr) + sizeof(iphdr));
					
					seq = bpf_ntohl(tcphdr.sent_seq);
					flow_info = make_flow_info(iphdr, tcphdr, #evt_type#);
					if (is_retrans(flow_info, seq, &prev_seq)) continue;

					data_len = set_data_len(flow_info, get_data_len(iphdr, tcphdr, flow_info, seq, prev_seq));
					
					if (is_event_occur(flow_info, data_len)) {
						event_occur(flow_info, data_len, #evt_type#);
						set_sampling_size(flow_info);
					}

					h_prev_seq.update(&flow_info, &seq);
				}
				return 0;
			}
		"""

	def __main__(self):
		self.__set_variable__()
		code = self.__set_header__()
		code += self.__set_map__()
		code += self.__set_common_func__()
		
		for func_name in self.func_name:
			code += self.__set_body_func__()
			code = code.replace("#function_name#", func_name)
			code = code.replace("#mbuf_pos#", self.mbuf_pos[func_name])
			code = code.replace("#pkt_cnt_pos#", self.pkt_cnt_pos[func_name])
			code = code.replace("#evt_type#", self.evt_type[func_name])
		
		return code





















