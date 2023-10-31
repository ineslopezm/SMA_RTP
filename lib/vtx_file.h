/* file format for vtx (video made of characters) */

// include for uint32_t
#include <stdint.h>

/* vtx_frame_t is included before every frame */
typedef struct {
    uint32_t length; // bytes
    uint32_t timestamp; // clock is 90,000 Hz
    uint16_t width, height;
    uint16_t format; 
    uint16_t padding; // Ensure 4 bytes alignment
} file_vtx_frame_header_t;

// format values
#define VTX_FORMAT_ONE_CHAR 0 // 1 byte per pixel

/* Original termvideo data:

Starts with 2 control sequences to clear terminal screen and position cursor at 0,0.
Lines end by new line (0x0a).
New frames start with 1 control sequence to position cursor at 0,0.

In vtx format these control characters are removed. Each frame is preceded by a vtx_frame_t struct.
Then, data is stored as lines ended by new line (0x0a)

*/