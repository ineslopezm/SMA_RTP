#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <netinet/in.h>

void configure_sockets(int *socket_RTP, int *socket_RTCP, struct in_addr remote_ip, bool is_multicast, int port, struct sockaddr_in *remote_RTP, struct sockaddr_in *remote_RTCP);
