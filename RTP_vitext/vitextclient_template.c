/* compile with PRINT_MISSING_PACKETS to activate this function in play_frame */
/*
gcc -DPRINT_MISSING_PACKETS=1 -Wshadow -Wpedantic -Wall -Wextra -Wstrict-overflow -fno-strict-aliasing -o vitextclient vitextclient.c ../lib/packet_buffer.c ../lib/configure_sockets.c ../lib/play_frame.c
*/

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
#include <sys/signalfd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../lib/packet_buffer.h"
#include "../lib/configure_sockets.h"
#include "../lib/rtp.h"
#include "../lib/vtx_rtp.h"

#include "../lib/play_frame.h"

#define MAX_PACKET_SIZE 1500
#define MAX_VITEXT_PAYLOAD_SIZE 1452

void get_arguments(int argc, char *argv[], struct in_addr *remote_ip, bool *is_multicast, int *port, uint32_t *ssrc, uint32_t *buffering_ms, bool *verbose, char *log_filename)
{
#define HELP printf("\nvitextclient [-h] [-b buffering] [-l log_filename] [-p port] [-s ssrc]  IP_ADDRESS\n"                                        \
                    "This implementation sends RTCP bye when the transmission ends. It also stops if it receives and RTCP bye from the client.\n\n" \
                    "[-h] to show this help\n"                                                                                                      \
                    "[-b buffering] to set the buffering in ms (default 100)\n"                                                                     \
                    "[-p port] to set the port\n"                                                                                                   \
                    "[-l log_filename] to set the log filename\n"                                                                                   \
                    "[-s ssrc] to set the ssrc of the client (only relevant if the client sends any RTCP message)\n"                                \
                    "\nIP_ADDRESS is the multicast address in which it listens\n");

    // default values
    *remote_ip = (struct in_addr){0};
    *is_multicast = false;
    *port = 5004;
    *log_filename = '\0';
    *buffering_ms = 100;
    *ssrc = 1;
    *verbose = false;

    int opt;
    while ((opt = getopt(argc, argv, "hvp:s:l:b:")) != -1)
    {
        switch (opt)
        {
        case 'h':
            HELP;
            break;
        case 'v':
            *verbose = true;
            break;
        case 'p':
            *port = (int)strtol(optarg, NULL, 10);
            if (*port < 1)
            {
                fprintf(stderr, "Port must be a positive number\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 's':
            *ssrc = (uint32_t)strtol(optarg, NULL, 10);
            break;

        case 'b':
            *buffering_ms = (uint32_t)strtol(optarg, NULL, 10);
            if (*buffering_ms < 1)
            {
                fprintf(stderr, "Buffering must be a positive number\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'l':
            if (strlen(optarg) <= 255)
            {
                strcpy(log_filename, optarg);
            }
            else
            {
                fprintf(stderr, "Log filename too long, must be up to 255\n");
                exit(EXIT_FAILURE);
            }
            *verbose = true;
            break;
        case '?':

        default:
            HELP;
            exit(EXIT_FAILURE);
        }
    }
    if (optind < argc)
    {
        int res = inet_pton(AF_INET, argv[optind], remote_ip);
        if (res < 1)
        {
            printf("\nInternet address string not recognized\n");
            exit(EXIT_FAILURE);
        }
        if (IN_CLASSD(ntohl(remote_ip->s_addr)))
        {
            *is_multicast = true;
        }
        else
        {
            *is_multicast = false;
        }
    }
    // ensure an address has been read in remote_ip

    if (remote_ip->s_addr == 0)
    {
        HELP;

        fprintf(stderr, "\n\nNo remote address given\n\n");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{
    // default values are assigned in get_arguments
    struct in_addr remote_ip;
    bool is_multicast;
    int port;
    char log_filename[256];
    uint32_t buffering_ms;
    bool verbose;
    uint32_t ssrc;

    get_arguments(argc, argv, &remote_ip, &is_multicast, &port, &ssrc, &buffering_ms, &verbose, log_filename);

    // config_sockets from configure_sockets.h
    int socket_RTP, socket_RTCP;
    struct sockaddr_in remote_RTP, remote_RTCP;

    // CONFIGURA EL SOCKET
    configure_sockets(&socket_RTP, &socket_RTCP, remote_ip, is_multicast, port, &remote_RTP, &remote_RTCP);

    /*************************/
    /* gets signal_fd and blocks signals, so that they will be processed inside the select
    Install it before buffer creation, so that it always enters select and exits through the appropriate code section freeing the memory */
    sigset_t sigInfo;
    sigemptyset(&sigInfo);
    sigaddset(&sigInfo, SIGINT);
    sigaddset(&sigInfo, SIGALRM);
    sigaddset(&sigInfo, SIGTERM);

    int signal_fd = signalfd(-1, &sigInfo, 0);
    if (signal_fd < 0)
    {
        printf("Error getting file descriptor for signals, error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // block SIGINT signal with sigprocmask
    if (sigprocmask(SIG_BLOCK, &sigInfo, NULL) < 0)
    {
        printf("Error installing signal, error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /**************************/

    // Create the log file
    FILE *log_file;
    if (verbose)
    {
        log_file = fopen(log_filename, "w");
        if (log_file == NULL)
        {
            fprintf(stderr, "Error creating the log file\n");
            exit(EXIT_FAILURE);
        }

        /* Put log_file in fully buffered mode, so that it writes to file only when it has a lot of data, or at the end */
        if (setvbuf(log_file, NULL, _IOFBF, 0) < 0)
        {
            perror("setvbuf");
            exit(EXIT_FAILURE);
        }

        fprintf(log_file, "Remote IP: %s, port %d, ssrc %d, buffering %dms, log_filename %s\n", inet_ntoa(remote_ip), port, ssrc, buffering_ms, log_filename);
    }

    // Create buffer
    // Parametros : number of blocks in the packet buffer   /* size in bytes of each data block */

    void *pbuf = pbuf_create(100, buffering_ms);

    // declaramos nuestro conjunto de señales y lo asociamos a nuestro
    // descriptor  
    fd_set conjunto_senales;
    FD_ZERO(&conjunto_senales);
    FD_SET(signal_fd, &conjunto_senales);



    // Create loop that receives packets and inserts them in the buffer, read from the buffer and plays them

    while (true)
    {
        int res = select(signal_fd, &conjunto_senales, NULL, NULL, NULL);
    }
}

int select(int n, fd_set *conjunto_senales, struct timeval *timeout) {
    return
}