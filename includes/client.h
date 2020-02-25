#ifndef _CLIENT_H_
# define _CLIENT_H_

# include <sys/socket.h>
# include <arpa/inet.h>

# include <stdlib.h>
# include <stdio.h>
# include <string.h>
# include <unistd.h>
# include <errno.h>
# include <netdb.h>

# define ADDR "127.0.0.1"
# define PORT 4242
# define BUFF_SIZE 128
# define KEY 4242

# define SOCKET_ERROR -1

typedef int SOCKET;

#endif
