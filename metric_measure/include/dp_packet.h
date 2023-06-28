#include "mbuf.h"

#define OVS_LOCKABLE __attribute__((lockable))
typedef unsigned long long uint64, uint64_t, ovs_be64, u64;
typedef long long int64, int64_t;
typedef unsigned int uint32, uint32_t, ovs_be32, u32;
typedef unsigned short uint16, uint16_t, ovs_be16, u16;
typedef unsigned char uint8, uint8_t, u8;
typedef uint32_t odp_port_t;

//#define ATOMIC(TYPE) std::atomic<TYPE>
#define ATOMIC(TYPE) int // cannot include <atomic.h> so temporary define int
#ifdef __GNUC__
#define OVSRCU_TYPE(TYPE) struct { ATOMIC(TYPE) p; }
#else
struct ovsrcu_pointer { ATOMIC(void *) p; };
#define OVSRCU_TYPE(TYPE) struct ovsrcu_pointer
#endif
//#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define ROUND_UP(X, Y) (DIV_ROUND_UP(X, Y) * (Y))
#define BITMAP_ULONG_BITS (sizeof(unsigned long) * CHAR_BIT)
#define BITMAP_N_LONGS(N_BITS) DIV_ROUND_UP(N_BITS, BITMAP_ULONG_BITS)
#define OVS_PACKED_ENUM __attribute__((__packed__))
#define TLV_MAX_OPT_SIZE 124
#define TLV_TOT_OPT_SIZE 252
#define PAD_PASTE2(x, y) x##y
#define PAD_PASTE(x, y) PAD_PASTE2(x, y)
#define PAD_ID PAD_PASTE(pad, __COUNTER__)
typedef uint8_t OVS_CACHE_LINE_MARKER[1];

typedef uint32_t ofp_port_t;
typedef uint32_t odp_port_t;
typedef uint32_t ofp11_port_t;

#ifndef __cplusplus
#define PADDED_MEMBERS_CACHELINE_MARKER(UNIT, CACHELINE, MEMBERS)   \
    union {                                                         \
        OVS_CACHE_LINE_MARKER CACHELINE;                            \
        struct { MEMBERS };                                         \
        uint8_t PAD_ID[ROUND_UP(sizeof(struct { MEMBERS }), UNIT)]; \
    }
#else
#define PADDED_MEMBERS_CACHELINE_MARKER(UNIT, CACHELINE, MEMBERS)           \
    struct struct_##CACHELINE { MEMBERS };                                  \
    union {                                                                 \
        OVS_CACHE_LINE_MARKER CACHELINE;                                    \
        struct { MEMBERS };                                                 \
        uint8_t PAD_ID[ROUND_UP(sizeof(struct struct_##CACHELINE), UNIT)];  \
    }
#endif

/* Mutex. */
struct OVS_LOCKABLE ovs_mutex {
    char lock[40]; // size만 맞추어 준다.
    const char *where;          /* NULL if and only if uninitialized. */
};

struct in_addr {
    uint32_t s_addr;
};

struct in6_addr {
    uint8_t s6_addr[16];
};

struct ct_addr {
    union {
        ovs_be32 ipv4;
        struct in6_addr ipv6;
        uint32_t ipv4_aligned;
        struct in6_addr ipv6_aligned;
    };
};

typedef union ovs_u128 {
    uint32_t u32[4];
    struct {
        uint64_t lo, hi;
    } u64;
} ovs_u128;

struct ct_endpoint {
    struct ct_addr addr;
    union {
        ovs_be16 port;
        struct {
            ovs_be16 icmp_id;
            uint8_t icmp_type;
            uint8_t icmp_code;
        };
    };
};

struct conn_key {
    struct ct_endpoint src;
    struct ct_endpoint dst;

    ovs_be16 dl_type;
    uint16_t zone;
    uint8_t nw_proto;
};

/* Doubly linked list head or element. */
struct ovs_list {
    struct ovs_list *prev;     /* Previous list element. */
    struct ovs_list *next;     /* Next list element. */
}i;

struct cmap_node {
    OVSRCU_TYPE(struct cmap_node *) next; /* Next node with same hash. */
};

enum OVS_PACKED_ENUM ct_conn_type {
    CT_CONN_TYPE_DEFAULT,
    CT_CONN_TYPE_UN_NAT,
};

struct conn {
    /* Immutable data. */
    struct conn_key key;
    struct conn_key rev_key;
    struct conn_key parent_key; /* Only used for orig_tuple support. */
    struct ovs_list exp_node;
    struct cmap_node cm_node;
    uint16_t nat_action;
    char *alg;
    struct conn *nat_conn; /* The NAT 'conn' context, if there is one. */

    /* Mutable data. */
    struct ovs_mutex lock; /* Guards all mutable fields. */
    ovs_u128 label;
    long long expiration;
    uint32_t mark;
    int seq_skew;

    /* Immutable data. */
    int32_t admit_zone; /* The zone for managing zone limit counts. */
    uint32_t zone_limit_seq; /* Used to disambiguate zone limit counts. */

    /* Mutable data. */
    bool seq_skew_dir; /* TCP sequence skew direction due to NATTing of FTP
                        * control messages; true if reply direction. */
    bool cleaned; /* True if cleaned from expiry lists. */

    /* Immutable data. */
    bool alg_related; /* True if alg data connection. */
    enum ct_conn_type conn_type;

    uint32_t tp_id; /* Timeout policy ID. */
};

struct ovs_key_ct_tuple_ipv4 {
    __be32 ipv4_src;
    __be32 ipv4_dst;
    __be16 src_port;
    __be16 dst_port;
    __u8   ipv4_proto;
};

struct ovs_key_ct_tuple_ipv6 {
    __be32 ipv6_src[4];
    __be32 ipv6_dst[4];
    __be16 src_port;
    __be16 dst_port;
    __u8   ipv6_proto;
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////
#define TUN_METADATA_NUM_OPTS 64
#define TUN_METADATA_TOT_OPT_SIZE 256

struct tun_metadata_loc_chain {
    struct tun_metadata_loc_chain *next;
    int offset;       /* In bytes, from start of 'opts', multiple of 4.  */
    int len;          /* In bytes, multiple of 4. */
};

struct tun_metadata_loc {
    int len;                    /* Sum of 'len' over elements in chain. */
    struct tun_metadata_loc_chain c;
};

struct hmap_node {
    size_t hash;                /* Hash value. */
    struct hmap_node *next;     /* Next in linked list. */
};

struct tun_meta_entry {
    struct hmap_node node;      /* In struct tun_table's key_hmap. */
    struct tun_metadata_loc loc;
    uint32_t key;               /* (class << 8) | type. */
    bool valid;                 /* True if allocated to a class and type. */
};

struct hmap {
    struct hmap_node **buckets; /* Must point to 'one' iff 'mask' == 0. */
    struct hmap_node *one;
    size_t mask;
    size_t n;
};

struct tun_table {
    /* TUN_METADATA<i> is stored in element <i>. */
    struct tun_meta_entry entries[TUN_METADATA_NUM_OPTS];

    /* Each bit represents 4 bytes of space, 0-bits are free space. */
    unsigned long alloc_map[BITMAP_N_LONGS(TUN_METADATA_TOT_OPT_SIZE / 4)];

    /* The valid elements in entries[], indexed by class+type. */
    struct hmap key_hmap;
};

struct geneve_opt {
    __be16  opt_class;
    u8  type;
#ifdef __LITTLE_ENDIAN_BITFIELD
    u8  length:5;
    u8  r3:1;
    u8  r2:1;
    u8  r1:1;
#else
    u8  r1:1;
    u8  r2:1;
    u8  r3:1;
    u8  length:5;
#endif
    u8  opt_data[];
};

struct tun_metadata {
    union { /* Valid members of 'opts'. When 'opts' is sorted into known types,
             * 'map' is used. When 'opts' is raw packet data, 'len' is used. */
        uint64_t map;                      /* 1-bit for each present TLV. */
        uint8_t len;                       /* Length of data in 'opts'. */
    } present;
    const struct tun_table *tab; /* Types & lengths for 'opts' and 'opt_map'. */

#if UINTPTR_MAX == UINT32_MAX
    uint8_t pad[4];             /* Pad to 64-bit boundary. */
#endif

    union {
        uint8_t u8[TUN_METADATA_TOT_OPT_SIZE]; /* Values from tunnel TLVs. */
        struct geneve_opt gnv[TLV_TOT_OPT_SIZE / sizeof(struct geneve_opt)];
    } opts;
};
/////////////////////////////////////////////////////////////////////////////////////////
#define CACHE_LINE_SIZE 64

/* Tunnel information used in flow key and metadata. */
struct flow_tnl {
    ovs_be32 ip_dst;
    struct in6_addr ipv6_dst;
    ovs_be32 ip_src;
    struct in6_addr ipv6_src;
    ovs_be64 tun_id;
    uint16_t flags;
    uint8_t ip_tos;
    uint8_t ip_ttl;
    ovs_be16 tp_src;
    ovs_be16 tp_dst;
    ovs_be16 gbp_id;
    uint8_t  gbp_flags;
    uint8_t erspan_ver;
    uint32_t erspan_idx;
    uint8_t erspan_dir;
    uint8_t erspan_hwid;
    uint8_t gtpu_flags;
    uint8_t gtpu_msgtype;
    uint8_t pad1[4];     /* Pad to 64 bits. */
    struct tun_metadata metadata;
};

union flow_in_port {
    odp_port_t odp_port;
    ofp_port_t ofp_port;
};

/* Datapath packet metadata */
struct pkt_metadata {
PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline0,
    uint32_t recirc_id;         /* Recirculation id carried with the
                                   recirculating packets. 0 for packets
                                   received from the wire. */
    uint32_t dp_hash;           /* hash value computed by the recirculation
                                   action. */
    uint32_t skb_priority;      /* Packet priority for QoS. */
    uint32_t pkt_mark;          /* Packet mark. */
    uint8_t  ct_state;          /* Connection state. */
    bool ct_orig_tuple_ipv6;
    uint16_t ct_zone;           /* Connection zone. */
    uint32_t ct_mark;           /* Connection mark. */
    ovs_u128 ct_label;          /* Connection label. */
    union flow_in_port in_port; /* Input port. */
    odp_port_t orig_in_port;    /* Originating in_port for tunneled packets */
    struct conn *conn;          /* Cached conntrack connection. */
    bool reply;                 /* True if reply direction. */
    bool icmp_related;          /* True if ICMP related. */
);

PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline1,
    union {                     /* Populated only for non-zero 'ct_state'. */
        struct ovs_key_ct_tuple_ipv4 ipv4;
        struct ovs_key_ct_tuple_ipv6 ipv6;   /* Used only if                */
    } ct_orig_tuple;                         /* 'ct_orig_tuple_ipv6' is set */
);

PADDED_MEMBERS_CACHELINE_MARKER(CACHE_LINE_SIZE, cacheline2,
    struct flow_tnl tunnel;     /* Encapsulating tunnel parameters. Note that
                                 * if 'ip_dst' == 0, the rest of the fields may
                                 * be uninitialized. */
);
};

//////////////////////////////////////////////////////////////////////
#define DP_PACKET_CONTEXT_SIZE 64
#define DPDK_NETDEV 1

enum OVS_PACKED_ENUM dp_packet_source {
    DPBUF_MALLOC,              /* Obtained via malloc(). */
    DPBUF_STACK,               /* Un-movable stack space or static buffer. */
    DPBUF_STUB,                /* Starts on stack, may expand into heap. */
    DPBUF_DPDK,                /* buffer data is from DPDK allocated memory.
                                * ref to dp_packet_init_dpdk() in dp-packet.c.
                                */
    DPBUF_AFXDP,               /* Buffer data from XDP frame. */
};

struct dp_packet {
#ifdef DPDK_NETDEV
    struct rte_mbuf mbuf;       /* DPDK mbuf */
#else
    void *base_;                /* First byte of allocated space. */
    uint16_t allocated_;        /* Number of bytes allocated. */
    uint16_t data_ofs;          /* First byte actually in use. */
    uint32_t size_;             /* Number of bytes in use. */
    uint32_t ol_flags;          /* Offloading flags. */
    uint32_t rss_hash;          /* Packet hash. */
    uint32_t flow_mark;         /* Packet flow mark. */
#endif
    enum dp_packet_source source;  /* Source of memory allocated as 'base'. */

    /* All the following elements of this struct are copied in a single call
     * of memcpy in dp_packet_clone_with_headroom. */
    uint16_t l2_pad_size;          /* Detected l2 padding size.
                                    * Padding is non-pullable. */
    uint16_t l2_5_ofs;             /* MPLS label stack offset, or UINT16_MAX */
    uint16_t l3_ofs;               /* Network-level header offset,
                                    * or UINT16_MAX. */
    uint16_t l4_ofs;               /* Transport-level header offset,
                                      or UINT16_MAX. */
    uint32_t cutlen;               /* length in bytes to cut from the end. */
    ovs_be32 packet_type;          /* Packet type as defined in OpenFlow */
    union {
        struct pkt_metadata md;
        uint64_t data[DP_PACKET_CONTEXT_SIZE / 8];
    };
};
/////////////////////////////////////////////////////////////////////
enum { NETDEV_MAX_BURST = 32 }; /* Maximum number packets in a batch. */

struct dp_packet_batch {
    size_t count;
    bool trunc; /* true if the batch needs truncate. */
    struct dp_packet *packets[NETDEV_MAX_BURST];
};

