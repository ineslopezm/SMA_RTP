/* 
Tries to connect to a TCP server at address 'server_ip'. The server must be started before the client. The server can be in the same or different system. The video served is selected when starting vitextTCPserver

Implementation:
Connects to TCP server.
Then reads the vtx file header. From this, it gathers the number of bytes of the next frame, it reads the frame and prints in the screen. With the timestamp of the header, we compute the time to wait before reading the next frame. 
This is repeated until the TCP connection is closed.

COMPILE as:
gcc -Wshadow -Wpedantic -Wall -Wextra -Wstrict-overflow -fno-strict-aliasing -o vitextTCPclient vitextTCPclient.c
*/

#include <sys/ioctl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/time.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <signal.h>

#include "../lib/vtx_file.h"

void get_arguments(int argc, char *argv[], struct in_addr *server_ip, int * server_port) {

    #define HELP printf("vitextTCPclient [-h] [-p server_port] server_ip \n" \
    "[-p server_port] to specify the server port\n" \
    "[-h] for help\n" \
    "server_ip      IP address of the server\n" \
    ); 

    // default values
    *server_port = 5004;
    server_ip ->s_addr = 0;

    int opt;
    while ((opt = getopt(argc, argv, "hp:")) != -1) {
        switch (opt) {
            case 'h':
                HELP
                break;
            case 'p':
                *server_port = (int) strtol(optarg, NULL, 10);
                if (*server_port < 1) {
                    fprintf(stderr, "Port must be a positive number\n");    
                    exit(EXIT_FAILURE);
                }
                break;
            case '?':

            default:
                HELP;
                exit(EXIT_FAILURE);
        }
    }

    if (optind < argc) {
        int res = inet_pton(AF_INET, argv[optind], server_ip );
        if (res < 1) {
            printf("\nInternet address string not recognized\n");
            exit(EXIT_FAILURE);
        }
    }

    // ensure an address has been read in server_ip
    if (server_ip ->s_addr == 0) {
        HELP;
        fprintf(stderr, "No remote address given\n");
        exit(EXIT_FAILURE);
    }
}

// set buffer size (reduce it for testing)
void set_recv_buffer(int sockfd) {
    // set recv buffer size to 4096 bytes, to reduce sending rate
    int recv_buffer_size = 4096;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &recv_buffer_size, sizeof(recv_buffer_size)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // print current recv buffer size
    int current_recv_buffer_size;
    socklen_t current_recv_buffer_size_len = sizeof(current_recv_buffer_size);
    if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &current_recv_buffer_size, &current_recv_buffer_size_len) < 0) {
        perror("getsockopt");
        exit(EXIT_FAILURE);
    }
    printf("Current recv buffer size: %d\n", current_recv_buffer_size);
}


int main(int argc, char *argv[]) {

    struct in_addr server_ip;
    int server_port;

    get_arguments(argc, argv, &server_ip, &server_port);

    // connect to TCP server
    int sockfd;
    struct sockaddr_in serv_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("ERROR opening socket");
        exit(EXIT_FAILURE);
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(server_port);
    serv_addr.sin_addr = server_ip;

    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR connecting to server");
        exit(EXIT_FAILURE);
    }
    
    set_recv_buffer(sockfd);

    // NOTE: to print in the scre3en, configure stdout in full buffered mode, so that it writes only when executing fflush(stdout) or when the buffer is full.
    // This reduces the number of write() syscalls, which is important for performance
    if (setvbuf(stdout, NULL, _IOFBF, 0) < 0) {
        perror("setvbuf");
        exit(EXIT_FAILURE);
    }

    file_vtx_frame_header_t frame_header;

    // clear screen
    printf("\033[2J");

    struct timeval start_time;
    char *frame = NULL; 

    struct timeval repetition_start_time, target_time, sleep_time;
    gettimeofday(&start_time, NULL); // reference time for video playback
    repetition_start_time = start_time; // repetition_start_time is used to compute the time to sleep in reference to the start of the current repetition
    uint32_t first_timestamp = 0;
    bool first_frame = true;

    float inter_frame_us; // interframe time in microseconds
    size_t current_frame_size = 0, frame_size; 

    int bytes_pending;
    int bytes_read;

    while (true) {
        // read frame header
        bytes_pending = sizeof(file_vtx_frame_header_t);

        uint8_t * frame_header_position =  (uint8_t *) &frame_header;

        while (bytes_pending > 0) {
            bytes_read = read(sockfd, frame_header_position, bytes_pending); 
            if (bytes_read <= 0) {
                // probably end of file, should check with errno
                exit(EXIT_SUCCESS);
            }
            bytes_pending -= bytes_read;
            frame_header_position += bytes_read;
        }

        // compute time to sleep
        if (first_frame) {
            // first_timestamp = frame_header.timestamp;
            first_frame = false;
            first_timestamp = frame_header.timestamp;

            // There is no relative time to which to compare the first frame
            inter_frame_us = 0;
        }
        else {
            uint32_t theoretical_from_start_us = (frame_header.timestamp - first_timestamp) / 90000.0 * 1000000.0;
            // convert to timeval
            struct timeval theoretical_from_start_tv;
            theoretical_from_start_tv.tv_sec = theoretical_from_start_us / 1000000;
            theoretical_from_start_tv.tv_usec = theoretical_from_start_us % 1000000;

            // add difference to start time
            timeradd(&repetition_start_time, &theoretical_from_start_tv, &target_time);

            // get current time
            struct timeval current_time;
            gettimeofday(&current_time, NULL);

            // calculate time to sleep in timeval
            timersub(&target_time, &current_time, &sleep_time);

            // calculate time to sleep
            inter_frame_us = sleep_time.tv_sec * 1000000 + sleep_time.tv_usec;
        }
    
        // ensure that terminal is big enough
        struct winsize terminal_size;
        ioctl(STDOUT_FILENO, TIOCGWINSZ, &terminal_size);

        // height + 1 because of the status line
        if (frame_header.width > terminal_size.ws_col || frame_header.height +1 > terminal_size.ws_row) {
            printf("Terminal is too small to display the video\n");
            printf("Terminal size: %d x %d, video size: %d x %d\n", terminal_size.ws_col, terminal_size.ws_row, frame_header.width, frame_header.height);
            exit(EXIT_FAILURE);
        }

        // Read frame
        // Allocate memory to contain both (1) control code to place cursor in top left corner and (2) frame data
        #define CURSOR_TOP_LEFT "\033[1;1H"
        frame_size = strlen(CURSOR_TOP_LEFT) +frame_header.length ;
        // only allocate more bytes for frame if it grows
        if (frame_size > current_frame_size) {
            frame = realloc(frame, frame_size);
            current_frame_size = frame_size;
        }
        
        // write the control code at the beginning of the frame
        sprintf(frame, CURSOR_TOP_LEFT);
        // read the frame data AFTER the control code
        // TODO: read UNTIL frame_heade.length bytes have been read
        bytes_pending = frame_header.length;
        char * frame_position = frame + strlen(CURSOR_TOP_LEFT);
        while (bytes_pending > 0) {
            bytes_read = read(sockfd, frame_position, bytes_pending);
            if (bytes_read <= 0) {
                printf("Error reading frame from TCP socket, missing bytes");
                exit(EXIT_FAILURE);
            }
            frame_position += bytes_read;
            bytes_pending -= bytes_read;
        }
        
        // play frame
        write(STDOUT_FILENO, frame, frame_size);
        
        printf("frame length: %d, timestamp: %d, width: %d, height: %d, format: %d, inter_frame_time %f\n", frame_header.length, frame_header.timestamp, frame_header.width, frame_header.height, frame_header.format, inter_frame_us);
        fflush(stdout);

        if (inter_frame_us < 0) {
            // This frame is late according to the absolute time at which it should be played,
            // There are many reasons for this, for example, the Operating System doing some time-consuming operation... or the system been too slow.
            // Some virtual machines may take very long to process syscalls, and the time may impact the video playback.
            // Just show this frame as soon as possible
            inter_frame_us = 0;
        }
        // actual sleep action
        usleep(inter_frame_us);
    }

    close(sockfd);
    return 0;

}