/* input: remote_ip address, is_multicast, port
 output: sockets opened and bind(ed), remoteRTP and remoteRTPC sockaddr_in. 

 If it is multicast address, sockets are bound to this address, otherwise it is bound to INADDR_ANY. If it is multicast address, there are some specific configurations to be done.
 */

#include "configure_sockets.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>


void configure_sockets(int *socket_RTP, int *socket_RTCP, struct in_addr remote_ip, bool is_multicast, int port, struct sockaddr_in *remote_RTP, struct sockaddr_in *remote_RTCP) {
        /* Creates sockets */
    if ((*socket_RTP = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("socket error\n");
        exit(EXIT_FAILURE);
    }
    if ((*socket_RTCP = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("socket error\n");
        exit(EXIT_FAILURE);
    }

    /* Configures socket */
    bzero(remote_RTP, sizeof(struct sockaddr_in));
    remote_RTP->sin_family = AF_INET;
    remote_RTP->sin_port = htons(port);
    remote_RTP->sin_addr = remote_ip;

    // // print remote_ip
    // char ip[INET_ADDRSTRLEN];
    // inet_ntop(AF_INET, &(remote_RTP->sin_addr), ip, INET_ADDRSTRLEN);
    // printf("Remote IP: %s", ip);

    bzero(remote_RTCP, sizeof(struct sockaddr_in));
    remote_RTCP -> sin_family = AF_INET;
    remote_RTCP->sin_addr = remote_ip;
    remote_RTCP->sin_port = htons(port + 1);


    /* configure SO_REUSEADDR, multiple instances can bind to the same multicast address/port */
    /* for unicast, only the last one receives the data, so that... it is not very practical */
    int enable = 1;
    if (setsockopt(*socket_RTP, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        printf("setsockopt(SO_REUSEADDR) failed");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(*socket_RTCP, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        printf("setsockopt(SO_REUSEADDR) failed");
        exit(EXIT_FAILURE);
    }

    if (is_multicast) {
    


        if (bind(*socket_RTP, (struct sockaddr *)remote_RTP, sizeof(struct sockaddr_in)) < 0) {
            printf("bind error\n");
            exit(EXIT_FAILURE);
        }

        // RTCP

        if (bind(*socket_RTCP, (struct sockaddr *)remote_RTCP, sizeof(struct sockaddr_in)) < 0) {
            printf("bind error\n");
            exit(EXIT_FAILURE);
        }

        /* setsockopt configuration for joining to mcast group */    
        struct ip_mreq mreq;
        mreq.imr_multiaddr = remote_ip;
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
        if (setsockopt(*socket_RTP, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            printf("setsockopt error");
            exit(EXIT_FAILURE);
        }
        // just one socket needs to join the mcast group

        /* commented: I do want packets to be sent to mcast, to allow running in the same system. For vod is not a problem (except for RTCP, for which I need to filter out own messages by SSRC). */
        /* Do not receive packets sent to the mcast address by this process */
        // unsigned char loop=0;
        // setsockopt(socket_RTP, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(unsigned char));
        // setsockopt(socket_RTCP, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(unsigned char));

    }
    else {

        struct sockaddr_in local_RTP, local_RTCP;
        bzero(&local_RTP, sizeof(struct sockaddr_in));
        local_RTP.sin_family = AF_INET;
        local_RTP.sin_port = htons(port);
        local_RTP.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(*socket_RTP, (struct sockaddr *)&local_RTP, sizeof(struct sockaddr_in)) < 0) {
            printf("bind error\n");
            exit(EXIT_FAILURE);
        }

        bzero(&local_RTCP, sizeof(struct sockaddr_in));
        local_RTCP = local_RTP;
        local_RTCP.sin_port = htons(port + 1);
        if (bind(*socket_RTCP, (struct sockaddr *)&local_RTCP, sizeof(struct sockaddr_in)) < 0) {
            printf("bind error\n");
            exit(EXIT_FAILURE);
        }
    }
}
