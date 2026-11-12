/* Connects to a non-loopback address (a TEST-NET-1 documentation address, never routed) so the gate can prove it sees it. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(9);
    inet_pton(AF_INET, "192.0.2.1", &a.sin_addr);
    fcntl(fd, F_SETFL, O_NONBLOCK);
    connect(fd, (struct sockaddr *)&a, sizeof a);
    close(fd);
    return 0;
}
