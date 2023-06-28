class ebpfCode:
	def __init__(self):
		self.function_name = ["syncTimeProtocol"]
	
	def __set_header__(self):
		return """
            #include <uapi/linux/bpf.h>
            #include <linux/if_ether.h>
            #include <linux/ip.h>
            #include <linux/tcp.h>
            #include <linux/udp.h>
            #include <linux/in.h>

			#define PING_PORT 5999
			#define LOCAL_HOST 16777343

            struct flow_info {
                u32 addr;
				u32 port;
            };

            struct event_data {
                u32 src_addr;
                u32 dst_addr;
                u64 send_ts;
                u64 recv_ts;
				u64 server_ts;
            };
        """

	def __set_map__(self):
		return """
			BPF_PERF_OUTPUT(xdp_events);
			BPF_DEVMAP(tx_port, 1);
			BPF_HASH(h_check_send, struct flow_info, u8);
			BPF_HASH(h_send_time, struct flow_info, u64);
			BPF_HASH(h_try_cnt, struct flow_info, u8);
			BPF_TABLE("hash", u16, u32, port_to_addr, 256);
			BPF_TABLE("hash", u16, u64, port_to_macaddr, 256);
		"""
	
	def __set_common_func__(self):
		return """
			static void fill_mac_data(struct ethhdr **eth, u16 src_port, u16 dst_port) {
				u64 *src_macaddr = port_to_macaddr.lookup(&src_port);
				u64 *dst_macaddr = port_to_macaddr.lookup(&dst_port);
				s16 i, shift = 0;

				if (!src_macaddr || !dst_macaddr) return;
				
				for (i = ETH_ALEN - 1; i >= 0; i--, shift++) {
					(*eth)->h_source[i] = ((*src_macaddr) >> (8 * shift));
					(*eth)->h_dest[i] = ((*dst_macaddr) >> (8 * shift));
				}
			}

			static u64 atoi(struct iphdr *iphdr, struct udphdr *udphdr) {
				u64 ts = 0;
				ts |= (iphdr->id); ts <<= 16;
				ts |= (iphdr->frag_off); ts <<= 16;
				ts |= (udphdr->source); ts <<= 16;
				ts |= (udphdr->dest); 
				return ts;
			}

			static u8 check_send(u16 port) {
				u32 *addr = port_to_addr.lookup(&port);
				u64 *macaddr = port_to_macaddr.lookup(&port);
				struct flow_info flow_info;
				u8 *check, *try_cnt;
				u8 val1 = 1, val2 = 0;

				if (!addr || !macaddr) return 0;
				
				flow_info.addr = *addr;
				flow_info.port = port;

				try_cnt = h_try_cnt.lookup(&flow_info);
				check = h_check_send.lookup(&flow_info);
				if (check) {
					if (try_cnt && *try_cnt <= 3) {
						(*try_cnt)++;
						h_try_cnt.update(&flow_info, try_cnt);
						return 0;
					}
				}
		
				h_send_time.delete(&flow_info);
				h_check_send.update(&flow_info, &val1);
				h_try_cnt.update(&flow_info, &val2);
				return 1;
			}

			static u8 check_recv(u32 addr, u16 port) {
				struct flow_info flow_info = {
					.addr = addr,
					.port = port
				};
				u8 *check = h_check_send.lookup(&flow_info);
				if (!check) return 0;
				h_check_send.delete(&flow_info);
				return 1;
			}

			static void update_send_time(u32 addr, u16 port) {
				struct flow_info flow_info = {
					.addr = addr,
					.port = port
				};
				u64 ts = bpf_ktime_get_boot_ns();
				h_send_time.update(&flow_info, &ts);
			}

			static void event_occur(struct xdp_md *ctx, struct iphdr *iphdr, struct udphdr *udphdr) {
				u64 recv_ts = bpf_ktime_get_boot_ns();
				struct flow_info flow_info = {
					.addr = iphdr->saddr,
					.port = bpf_ntohs(udphdr->len)
				};
				u64 *send_ts = h_send_time.lookup(&flow_info);
				u64 server_ts = atoi(iphdr, udphdr);
				struct event_data data = {};

				if (!send_ts) return;
				data.src_addr = bpf_ntohl(iphdr->daddr);
				data.dst_addr = bpf_ntohl(iphdr->saddr);
				data.send_ts = *send_ts;
				data.recv_ts = recv_ts;
				data.server_ts = server_ts;

				xdp_events.perf_submit(ctx, &data, sizeof(data));

				h_send_time.delete(&flow_info);
			}
			"""

	def __set_main_func__(self):
		return """
			int syncTimeProtocol(struct xdp_md *ctx) {
				void *data_begin = (void *)(long) ctx->data;
				void *data_end = (void *)(long) ctx->data_end;
				struct ethhdr *eth;
				struct iphdr *iphdr;
				struct udphdr *udphdr;
				
				u64 ts;
				u8 can_send;
				u8 can_port_match;

				u32 *src_addr;
				u32 *dst_addr;
				u16 src_port;
				u16 dst_port;

				u16 hash_key;

				eth = data_begin;
				if ((void *)(eth + 1) > data_end) return XDP_PASS;
				if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

				iphdr = (struct iphdr *) (((void *) eth) + ETH_HLEN);
				if ((void *)(iphdr + 1) > data_end) return XDP_PASS;
				if (iphdr->protocol != IPPROTO_UDP) return XDP_PASS;
				
				udphdr = (struct udphdr *)(iphdr + 1);
				if ((void *)(udphdr + 1) > data_end) return XDP_PASS;

				if (iphdr->daddr == LOCAL_HOST && (check_send(bpf_ntohs(udphdr->dest)))) {
					src_port = bpf_htons(PING_PORT);
					dst_port = bpf_ntohs(udphdr->dest);

					hash_key = PING_PORT;
					src_addr = port_to_addr.lookup(&hash_key);

					hash_key = bpf_ntohs(udphdr->dest);
					dst_addr = port_to_addr.lookup(&hash_key);

					if (!dst_addr || !src_addr) return XDP_PASS;
					iphdr->saddr = *src_addr;
					iphdr->daddr = *dst_addr;
					udphdr->source = src_port;

					fill_mac_data(&eth, bpf_ntohs(src_port), dst_port);
					update_send_time(*dst_addr, bpf_ntohs(udphdr->dest));

					return tx_port.redirect_map(0, 0);
				}
				else if (check_recv(iphdr->saddr, bpf_ntohs(udphdr->len))) {
					event_occur(ctx, iphdr, udphdr);
					return XDP_DROP;
				}
				return XDP_PASS;
			} 
		"""
	
	def __main__(self):
		code = self.__set_header__()
		code += self.__set_map__()
		code += self.__set_common_func__()
		code += self.__set_main_func__()

		return code




















