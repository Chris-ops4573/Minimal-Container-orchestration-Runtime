#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>

#define PORT 8080

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT)
    };

    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }

    char input[1024];
    char buffer[1024];

    while (1) {
        printf("> ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin))
            break;

        write(sock, input, strlen(input));

        int n = read(sock, buffer, sizeof(buffer) - 1);
        if (n <= 0) break;

        buffer[n] = '\n';
        if(strstr(buffer, "<<END>>")){
            break;
        }

        buffer[n] = '\0';
        printf("%s", buffer);
    }

    close(sock);
}