/* packet buffer to be used for rtp/vitext data (stores rtp/vitext specific data)*/

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

// allocates a packet buffer. 
// Returns NULL if allocation fails, otherwise returns a pointer to the packet buffer
void *pbuf_create ( 
    size_t  total_blocks,    /* number of blocks in the packet buffer */
    size_t block_size           /* size in bytes of each data block */  );

void pbuf_destroy (void *pbuf);

// Returns 0 on success, -1 on failure
// Error if:
// 1. pbuf is NULL
// 2. data is NULL
// 3. data_length is 0
// 4. data_length is greater than block_size
int pbuf_insert(void *pbuf, 
    uint32_t packet_number, // rtp format
    uint32_t timestamp, 
    bool is_last_packet,   
    uint32_t offset,    // vtx_rtp format
    uint16_t video_width, 
    uint16_t video_height,  
    uint8_t *data,       // received data
    uint16_t data_length // length of data inserted
    );

// On error, returns NULL.
// On success, returns a pointer to the data in the packet buffer, fills timestamp, ... etc.
// The data is not copied. The user should not access to more than
// data_length bytes of the returned pointer.
// Error if:
// 1. pbuf is NULL
// 2. packet_number is not in the packet buffer
void * pbuf_retrieve(void *pbuf, 
    uint32_t packet_number, // rtp
    uint32_t *timestamp, 
    bool *is_last_packet, 
    uint32_t *offset, // vtx_rtp format
    uint16_t *video_width, 
    uint16_t *video_height,
    uint16_t *data_length // length of data stored in the block
    ); 

// Returns 0 on success, -1 on failure
// Error if:
// 1. pbuf is NULL
// 2. packet_number is not in the packet buffer
// Returns the timestamp of the packet_number in timestamp.
// Note that it could be acceptable to try to retrieve the timestamp of a packet that is not in the packet buffer, so the error may not be fatal.
int get_timestamp(void *pbuf, uint32_t packet_number, uint32_t *timestamp);


// Checks for lowest timestamp in the interval between packet with 'first_seq' and 'last_seq', both included. Assumes lowest timestamp is in lowest sequence number
// Returns 0 if successful, -1 if not (i.e. no timestamp found)
// On success, 
// - lowest_timestamp is set to the lowest timestamp, and 
// - lowest_seq is set to the sequence number of the lowest timestamp
int get_lowest_timestamp(void *buffer, uint32_t *lowest_timestamp, uint16_t *lowest_seq, uint16_t first_seq, uint16_t last_seq);