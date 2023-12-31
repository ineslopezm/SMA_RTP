/*
 * rtp.h  --  RTP header file 
 */

/* Modified for use in UC3M lab */

// #include "types.h"   /* changed from <sys/types.h> by Akira 12/27/01 */
// #include "sysdep.h"

#include <stdint.h>

/*
 * System endianness -- determined by autoconf.
 */
#ifdef WORDS_BIGENDIAN
#define RTP_BIG_ENDIAN 1
#else
#define RTP_LITTLE_ENDIAN 1
#endif

/*
 * Current protocol version.
 */
#define RTP_VERSION    2

#define RTP_SEQ_MOD (1<<16)
#define RTP_MAX_SDES 255      /* maximum text length for SDES */

typedef enum {
    RTCP_SR   = 200,
    RTCP_RR   = 201,
    RTCP_SDES = 202,
    RTCP_BYE  = 203,
    RTCP_APP  = 204
} rtcp_type_t;

typedef enum {
    RTCP_SDES_END   = 0,
    RTCP_SDES_CNAME = 1,
    RTCP_SDES_NAME  = 2,
    RTCP_SDES_EMAIL = 3,
    RTCP_SDES_PHONE = 4,
    RTCP_SDES_LOC   = 5,
    RTCP_SDES_TOOL  = 6,
    RTCP_SDES_NOTE  = 7,
    RTCP_SDES_PRIV  = 8
} rtcp_sdes_type_t;

/* ----------------------------------------------------------------------------------------------------- */
/*
 * RTP data header
 */
typedef struct {
#if RTP_BIG_ENDIAN
    unsigned int version:2;   /* protocol version */
    unsigned int p:1;         /* padding flag */
    unsigned int x:1;         /* header extension flag */
    unsigned int cc:4;        /* CSRC count */
    unsigned int m:1;         /* marker bit */
    unsigned int pt:7;        /* payload type */
#elif RTP_LITTLE_ENDIAN
    unsigned int cc:4;        /* CSRC count */
    unsigned int x:1;         /* header extension flag */
    unsigned int p:1;         /* padding flag */
    unsigned int version:2;   /* protocol version */
    unsigned int pt:7;        /* payload type */
    unsigned int m:1;         /* marker bit */
#else
#error Define one of RTP_LITTLE_ENDIAN or RTP_BIG_ENDIAN
#endif
    unsigned int seq:16;      /* sequence number */
    uint32_t ts;               /* timestamp */
    uint32_t ssrc;             /* synchronization source */
    /* UC3M: in the example of the RFC, here appears a csrc field. Our application setting does not require CSRCs so the best option is to remove them */
} rtp_hdr_t;



/* UC3M : next part is RTCP-specific */

/* ----------------------------------------------------------------------------------------------------- */
/*
 * RTCP common header word
 */
typedef struct {
#if RTP_BIG_ENDIAN
    unsigned int version:2;   /* protocol version */
    unsigned int p:1;         /* padding flag */
    unsigned int count:5;     /* varies by packet type */
#elif RTP_LITTLE_ENDIAN
    unsigned int count:5;     /* varies by packet type */
    unsigned int p:1;         /* padding flag */
    unsigned int version:2;   /* protocol version */
#else
#error Define one of RTP_LITTLE_ENDIAN or RTP_BIG_ENDIAN
#endif
    unsigned int pt:8;        /* RTCP packet type */
    unsigned int length:16;   /* pkt len in words, w/o this word */
} rtcp_common_t;

/*
 * Big-endian mask for version, padding bit and packet type pair
 * XXX?
 */
#define RTCP_VALID_MASK (0xc000 | 0x2000 | 0xfe)
#define RTCP_VALID_VALUE ((RTP_VERSION << 14) | RTCP_SR)

/*
 * Reception report block
 */
typedef struct {
    uint32_t ssrc;             /* data source being reported */
    unsigned int fraction:8;  /* fraction lost since last SR/RR */
    int lost:24;              /* cumul. no. pkts lost (signed!) */
    uint32_t last_seq;         /* extended last seq. no. received */
    uint32_t jitter;           /* interarrival jitter */
    uint32_t lsr;              /* last SR packet from this source */
    uint32_t dlsr;             /* delay since last SR packet */
} rtcp_rr_t;

/*
 * SDES item
 */
typedef struct {
    uint8_t type;              /* type of item (rtcp_sdes_type_t) */
    uint8_t length;            /* length of item (in octets) */
    char data[1];             /* text, not null-terminated */
} rtcp_sdes_item_t;


/*
 * One RTCP packet
 */
typedef struct {
    rtcp_common_t common;     /* common header */
    union {
        /* sender report (SR) */
        struct {
            uint32_t ssrc;     /* sender generating this report */
            uint32_t ntp_sec;  /* NTP timestamp */
            uint32_t ntp_frac;
            uint32_t rtp_ts;   /* RTP timestamp */
            uint32_t psent;    /* packets sent */
            uint32_t osent;    /* octets sent */ 
            rtcp_rr_t rr[1];  /* variable-length list */
            			/* UC3M: this is a generic definition. Note that in a typical application this is not known in compilation time, but depends on the number of peers you have. Real applications may not be able to use static declarations -such as this- to fill this part of the information.
            			Fortunately, in our specific case we know from the very specification of the application the number of peers we are having: 1.
            			So this definition is fine for you */
        } sr;

        /* reception report (RR) */
        struct {
            uint32_t ssrc;     /* receiver generating this report */
            rtcp_rr_t rr[1];  /* variable-length list */
        } rr;

        /* source description (SDES) */
        struct rtcp_sdes {
            uint32_t src;      /* first SSRC/CSRC */
            rtcp_sdes_item_t item[1]; /* list of SDES items */
            			/* UC3M: this is a generic definition. This is similar to case stated for the Sender Report. 
            			You should put here the exact number of SDES items  you plan to use,... IN THIS CASE YOU WANT TO USE A DIFFERENT NUMBER, SO PLEASE CHANGE THIS VALUE */
        } sdes;

        /* BYE */
        struct {
            uint32_t src[1];   /* list of sources */
            		/* UC3M: similar consideration to the previous SR and SDES case */
            		/* UC3M: we can't express trailing text in this way. If you are using the same message all the time, count the characters, and define a char text[CHAR_NUM+1] field - remember always to finish a string with '\0' */
        } bye;
    } r;
} rtcp_t;

typedef struct rtcp_sdes rtcp_sdes_t;

/*
 * Per-source state information
 */
/* UC3M: this is the structure in which you introduce the information regarding the peer sending RTCP info to you */
#define MAX_LEN_SDES_ITEM 128

typedef struct {
  uint16_t max_seq;        /* highest seq. number seen */
  uint32_t cycles;         /* shifted count of seq. number cycles */
  uint32_t base_seq;       /* base seq number */
  uint32_t bad_seq;        /* last 'bad' seq number + 1 */
  uint32_t probation;      /* sequ. packets till source is valid */
  uint32_t received;       /* packets received */
  uint32_t expected_prior; /* packet expected at last interval */
  uint32_t received_prior; /* packet received at last interval */
  uint32_t transit;        /* relative trans time for prev pkt */
  uint32_t jitter;         /* estimated jitter */
  /* ... */
  /* UC3M specific definitions */
  char CNAME[MAX_LEN_SDES_ITEM]; /* stores the last CNAME value advertised by the peer. Must be a '\0' terminated string. */
  char TOOL[MAX_LEN_SDES_ITEM]; /* stores the last TOOL value advertised by the peer. Must be a '\0' terminated string. */
} source;
