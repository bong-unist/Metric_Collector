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
		"""
	
	def __set_map__(self):
		return """
			BPF_PERF_OUTPUT(xdp_events);
			BPF_TABLE("hash", u8, u32, t_addr, 1);
		"""

	def __set_common_func__(self):
		return """
			static u16 calc_ip_checksum(struct iphdr *iphdr) {
				u32 sum = 0;
				u16 checksum = 0;
				u16 data[10];
				s16 i;

				bpf_probe_read_kernel(data, sizeof(data), iphdr);
				for (i = 0; i < 10; i++) sum += data[i];
				checksum += sum;
				checksum += (sum >> 16);
				checksum += (sum >> 16);
				checksum = ~checksum;
				return checksum;
			}

			static void swap_packet(struct iphdr **iphdr, struct ethhdr **eth) {
				u32 taddr;
				unsigned char t_macaddr;
				s16 i;

				taddr = (*iphdr)->saddr;
				(*iphdr)->saddr = (*iphdr)->daddr;
				(*iphdr)->daddr = taddr;

				for (i = 0; i < 6; i++) {
					t_macaddr = (*eth)->h_source[i];
					(*eth)->h_source[i] = (*eth)->h_dest[i];
					(*eth)->h_dest[i] = t_macaddr;
				}
				return;
			}

			static void fill_data(struct iphdr **iphdr, struct udphdr **udphdr) {
				u64 ts = bpf_ktime_get_boot_ns();
				(*udphdr)->len = (*udphdr)->dest;
				(*iphdr)->id = (*iphdr)->frag_off = 0;
				(*udphdr)->source = (*udphdr)->dest = 0;
				(*iphdr)->id |= (ts >> 48);
				(*iphdr)->frag_off |= (ts >> 32);
				(*udphdr)->source |= (ts >> 16);
				(*udphdr)->dest |= ts;
			}

			static u32 get_host(void) {
				u8 key = 1;
				u32 *addr;

				addr = t_addr.lookup(&key);
				if (addr) return *addr;
				return 0;
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

				u32 addr;
				u16 port;

				eth = data_begin;
                if ((void *)(eth + 1) > data_end) return XDP_PASS;
                if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

                iphdr = (struct iphdr *) (((void *) eth) + ETH_HLEN);
                if ((void *)(iphdr + 1) > data_end) return XDP_PASS;
                if (iphdr->protocol != IPPROTO_UDP) return XDP_PASS;

                udphdr = (struct udphdr *)(iphdr + 1);
                if ((void *)(udphdr + 1) > data_end) return XDP_PASS;

				addr = iphdr->daddr;
				port = bpf_ntohs(udphdr->source);

				if (addr == get_host() && port == PING_PORT) {
					swap_packet(&iphdr, &eth);
					iphdr->check = calc_ip_checksum(iphdr);
					fill_data(&iphdr, &udphdr);
					return XDP_TX;
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
















