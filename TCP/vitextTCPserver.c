/* 
Waits for a TCP client to connect and sends the video file indicated in the command line to it. After delivering the video, exits (does not wait for a new client).

Implementation details:
This server knows NOTHING about the content it serves. It just sends whatever it reads from the video file.
Reads from file in chunks of BLOCK_SIZE. Its an arbitrary value that can be changed .


COMPILE as:
gcc -Wshadow -Wpedantic -Wall -Wextra -Wstrict-overflow -fno-strict-aliasing -o vitextTCPserver vitextTCPserver.c

EXECUTE (example)
./vitextTCPserver video.vtx

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


// size of the block to read/send,  
#define BLOCK_SIZE 1024

void get_arguments(int argc, char *argv[], char *filename,  int* local_port, bool *verbose) {

    #define HELP printf("vitextTCPserver [-h] [-v] [-p local_port] filename\n" \
    "[-h] for help\n" \
    "[-v] for verbose (prints a '.' every time a block of data is sent) \n" \
    );

    // default values
    *filename = '\0';
    *verbose = false;
    *local_port = 5004;

    int opt;
    while ((opt = getopt(argc, argv, "hvp:")) != -1) {
        switch (opt) {
            case 'h':
                HELP;
                break;
            case 'v':
                *verbose = true;
                break;
            case 'p':
                *local_port = (int) strtol(optarg, NULL, 10);
                if (*local_port < 1) {
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
        if (strlen(argv[optind]) <=255 ) 
        {
            strcpy(filename, argv[optind]);
        }
        else {
            fprintf(stderr, "Filename too long, must be up to 255\n");
            exit(EXIT_FAILURE);
        }
    }

    if (strlen(filename) == 0) {
        fprintf(stderr, "No filename given\n");
        exit(EXIT_FAILURE);
    }
}


int main(int argc, char *argv[]) {

    char filename[255];
    bool verbose;
    int local_port;

    get_arguments(argc, argv, filename, &local_port, &verbose);
    
    // open file
    FILE *fp;
    fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("Error opening file %s", filename);
        exit(EXIT_FAILURE);
    }

    // ***** TCP server ******
    // wait for TCP client
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // accept connections on any IP address of this machine, port 'local_port'
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(local_port);
    // Forcefully attaching socket to the local_port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 1) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    if (verbose) {
        printf("Client connected from %s:%d", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
    }


    char datatosend[BLOCK_SIZE];
    ssize_t bytes_read;
    ssize_t bytes_pending, bytes_sent;
    char * datatosend_position;

    // Read and send video
    while ( (bytes_read =fread(datatosend, 1, BLOCK_SIZE, fp)) > 0) {

        bytes_pending = bytes_read;
        datatosend_position =  (char *) datatosend;

        while (bytes_pending > 0) {
            // try to send everything in one call, but may not be able to
            bytes_sent = write(new_socket, datatosend_position, bytes_pending);
            bytes_pending -= bytes_sent;
            datatosend_position += bytes_sent;
        }

        if (verbose) {
            printf("."); fflush (stdout);
        }
    }

    fclose(fp);
    close(new_socket);
    close(server_fd);
    return 0;
}