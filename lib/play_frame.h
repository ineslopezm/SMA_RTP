
// play the FRAME starting with sequence number seq.
// The frame can be composed of multiple packets, the function will retrieve all the packets and play them
// It copies the data into the buffer, and then plays it. 
// It cannot play the data directly from the buffer, because the data may not be complete. Only plays complete frames
//
// returns 0 if successful, -1 if there are missing packets
// exits if the size is not appropriate
//
// buffer is a packet buffer in which seq is queried
// seq returns the last part of the frame read
// log_file: if verbose and not NULL, it prints # and = according to the specification
// 
int play_frame(void* buffer, uint16_t *seq, bool verbose, FILE *log_file);