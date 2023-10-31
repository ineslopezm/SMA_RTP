/* RTP header format for vtx (video made of characters) */

// include for uint32_t
#include <stdint.h>

/* rtp_vtx_frame_t is included in every after RTP header, and before the data */
/* BIG ENDIAN*/
typedef struct {
    uint32_t off; // offset in bytes
    uint16_t height;
    uint16_t width;
} rtp_vtx_frame_header_t;

// payload
#define RTP_VTX_PAYLOAD_ONE_CHAR 97 // 1 byte per pixel

