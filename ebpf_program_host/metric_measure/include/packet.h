#define RTE_ETHER_ADDR_LEN  6
#define __rte_aligned(a) __attribute__((__aligned__(a)))
#define __rte_packed __attribute__((__packed__))
#define rte_pktmbuf_mtod_offset(m, t, o)    \
    ((t)((char *)(m)->buf_addr + (m)->data_off + (o)))
#define rte_pktmbuf_mtod(m, t) rte_pktmbuf_mtod_offset(m, t, 0)
#define RTE_PTYPE_L3_IPV4                   0x00000010
#define RTE_BE16(v) (rte_be16_t)(v)
#define RTE_BE32(v) (rte_be32_t)(v)
#define RTE_BE64(v) (rte_be64_t)(v)

#define IPPROTO_IP         0
#define IPPROTO_HOPOPTS    0
#define IPPROTO_ICMP       1
#define IPPROTO_IPIP       4
#define IPPROTO_TCP        6
#define IPPROTO_UDP       17
#define IPPROTO_IPV6      41
#define IPPROTO_ROUTING   43
#define IPPROTO_FRAGMENT  44
#define IPPROTO_GRE       47
#define IPPROTO_ESP       50
#define IPPROTO_AH        51
#define IPPROTO_ICMPV6    58
#define IPPROTO_NONE      59
#define IPPROTO_DSTOPTS   60
#define IPPROTO_SCTP     132

#define INET6_ADDRSTRLEN 46

#define RTE_ETHER_TYPE_IPV4 0x0800 /**< IPv4 Protocol. */
#define RTE_ETHER_TYPE_IPV6 0x86DD /**< IPv6 Protocol. */
#define RTE_ETHER_TYPE_ARP  0x0806 /**< Arp Protocol. */
#define RTE_ETHER_TYPE_RARP 0x8035 /**< Reverse Arp Protocol. */
#define RTE_ETHER_TYPE_VLAN 0x8100 /**< IEEE 802.1Q VLAN tagging. */
#define RTE_ETHER_TYPE_QINQ 0x88A8 /**< IEEE 802.1ad QinQ tagging. */
#define RTE_ETHER_TYPE_QINQ1 0x9100 /**< Deprecated QinQ VLAN. */
#define RTE_ETHER_TYPE_QINQ2 0x9200 /**< Deprecated QinQ VLAN. */
#define RTE_ETHER_TYPE_QINQ3 0x9300 /**< Deprecated QinQ VLAN. */
#define RTE_ETHER_TYPE_PPPOE_DISCOVERY 0x8863 /**< PPPoE Discovery Stage. */
#define RTE_ETHER_TYPE_PPPOE_SESSION 0x8864 /**< PPPoE Session Stage. */
#define RTE_ETHER_TYPE_ETAG 0x893F /**< IEEE 802.1BR E-Tag. */
#define RTE_ETHER_TYPE_1588 0x88F7
    /**< IEEE 802.1AS 1588 Precise Time Protocol. */
#define RTE_ETHER_TYPE_SLOW 0x8809 /**< Slow protocols (LACP and Marker). */
#define RTE_ETHER_TYPE_TEB  0x6558 /**< Transparent Ethernet Bridging. */
#define RTE_ETHER_TYPE_LLDP 0x88CC /**< LLDP Protocol. */
#define RTE_ETHER_TYPE_MPLS 0x8847 /**< MPLS ethertype. */
#define RTE_ETHER_TYPE_MPLSM 0x8848 /**< MPLS multicast ethertype. */
#define RTE_ETHER_TYPE_ECPRI 0xAEFE /**< eCPRI ethertype (.1Q supported). */
/*
struct in_addr {
    uint32_t s_addr;
};

struct in6_addr {
    uint8_t s6_addr[16];
};
*/
typedef uint16_t rte_be16_t; /**< 16-bit big-endian value. */
typedef uint32_t rte_be32_t; /**< 32-bit big-endian value. */
typedef uint64_t rte_be64_t; /**< 64-bit big-endian value. */
typedef uint16_t rte_le16_t; /**< 16-bit little-endian value. */
typedef uint32_t rte_le32_t; /**< 32-bit little-endian value. */
typedef uint64_t rte_le64_t; /**< 64-bit little-endian value. */

struct rte_ether_addr {
    uint8_t addr_bytes[RTE_ETHER_ADDR_LEN]; /**< Addr bytes in tx order */
} __rte_aligned(2);

struct rte_ether_hdr {
    struct rte_ether_addr d_addr; /**< Destination address. */
    struct rte_ether_addr s_addr; /**< Source address. */
    uint16_t ether_type;      /**< Frame type. */
} __rte_aligned(2);

__extension__
struct rte_ipv4_hdr {
    union {
        uint8_t version_ihl;    /**< version and header length */
        struct {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
            uint8_t ihl:4;
            uint8_t version:4;
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
            uint8_t version:4;
            uint8_t ihl:4;
#else
#error "setup endian definition"
#endif
        };
    };
    uint8_t  type_of_service;   /**< type of service */
    rte_be16_t total_length;    /**< length of packet */
    rte_be16_t packet_id;       /**< packet ID */
    rte_be16_t fragment_offset; /**< fragmentation offset */
    uint8_t  time_to_live;      /**< time to live */
    uint8_t  next_proto_id;     /**< protocol ID */
    rte_be16_t hdr_checksum;    /**< header checksum */
    rte_be32_t src_addr;        /**< source address */
    rte_be32_t dst_addr;        /**< destination address */
} __rte_packed;

struct rte_udp_hdr {
    rte_be16_t src_port;    /**< UDP source port. */
    rte_be16_t dst_port;    /**< UDP destination port. */
    rte_be16_t dgram_len;   /**< UDP datagram length */
    rte_be16_t dgram_cksum; /**< UDP datagram checksum */
} __rte_packed;

static inline void *
rte_memcpy(void *dst, const void *src, size_t n)
{
    return memcpy(dst, src, n);
}

#define rte_bswap32(x) __builtin_bswap32(x)
#define rte_be_to_cpu_32(x) rte_bswap32(x)

struct rte_vlan_hdr {
    uint16_t vlan_tci; /**< Priority (3) + CFI (1) + Identifier Code (12) */
    uint16_t eth_proto;/**< Ethernet type of encapsulated frame. */
} __rte_packed;

struct rte_ipv6_hdr {
    rte_be32_t vtc_flow;    /**< IP version, traffic class & flow label. */
    rte_be16_t payload_len; /**< IP packet length - includes header size */
    uint8_t  proto;     /**< Protocol, next header. */
    uint8_t  hop_limits;    /**< Hop limits. */
    uint8_t  src_addr[16];  /**< IP address of source host. */
    uint8_t  dst_addr[16];  /**< IP address of destination host(s). */
} __rte_packed;

__extension__
struct rte_tcp_hdr {
    rte_be16_t src_port; /**< TCP source port. */
    rte_be16_t dst_port; /**< TCP destination port. */
    rte_be32_t sent_seq; /**< TX data sequence number. */
    rte_be32_t recv_ack; /**< RX data acknowledgment sequence number. */
    union {
        uint8_t data_off;
        struct {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
            uint8_t rsrv:4;
            uint8_t dt_off:4;   /**< Data offset. */
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
            uint8_t dt_off:4;   /**< Data offset. */
            uint8_t rsrv:4;
#else
#error "setup endian definition"
#endif
        };

    };
    union {
        uint8_t tcp_flags;  /**< TCP flags */
        struct {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
            uint8_t fin:1;
            uint8_t syn:1;
            uint8_t rst:1;
            uint8_t psh:1;
            uint8_t ack:1;
            uint8_t urg:1;
            uint8_t ecne:1;
            uint8_t cwr:1;
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
            uint8_t cwr:1;
            uint8_t ecne:1;
            uint8_t urg:1;
            uint8_t ack:1;
            uint8_t psh:1;
            uint8_t rst:1;
            uint8_t syn:1;
            uint8_t fin:1;
#else
#error "setup endian definition"
#endif
        };
    };
    rte_be16_t rx_win;   /**< RX flow control window. */
    rte_be16_t cksum;    /**< TCP checksum. */
    rte_be16_t tcp_urp;  /**< TCP urgent pointer, if any. */
} __rte_packed;


