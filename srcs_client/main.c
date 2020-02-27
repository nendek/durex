#include "client.h"

static void		encrypt_msg(char *str, const int len)
{
	int i = 0;

	while (i < len - 1)
	{
		str[i] ^= KEY;
		i++;
	}
}

static void		decrypt_msg(char *str, const int len)
{
	int i = 0;
	
	while (i < len - 1)
	{
		str[i] ^= KEY;
		i++;
	}
}

static int		create_client(void)
{
	int			sock = 0;
	struct sockaddr_in	sin;

	memset(&sin, 0, sizeof(sin));
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == SOCKET_ERROR)
	{
		perror("socket");
		exit(errno);
	}
	sin.sin_family = AF_INET;
	sin.sin_port = htons(PORT);
	sin.sin_addr.s_addr = inet_addr(ADDR);
	if ((connect(sock, (const struct sockaddr *)&sin, sizeof(sin))) == SOCKET_ERROR)
	{
		perror("connect");
		exit(errno);
	}
	return (sock);
}

static void		write_server(const SOCKET *sock, char *buffer, const int len)
{
	encrypt_msg(buffer, len);
	if (send(*sock, buffer, len,  0) < 0)
	{
		perror("send()");
		exit(errno);
	}
}

static int		read_server(const SOCKET *sock, char *buffer)
{
	int n = 0;

	if((n = recv(*sock, buffer, BUFF_SIZE - 1, 0)) < 0)
	{
		perror("recv()");
		exit(errno);
	}
	decrypt_msg(buffer,n);
	buffer[n] = '\0';
	return (n);
}

static int		client(const SOCKET *sock)
{
	fd_set	readfds;
	fd_set	active_fds;
	char	buffer[BUFF_SIZE];
	int	ret;

	FD_ZERO(&active_fds);
	FD_SET(STDIN_FILENO, &active_fds);
	FD_SET(*sock, &active_fds);
	while (1)
	{
		readfds = active_fds;
		if(select(*sock + 1, &readfds, NULL, NULL, NULL) == -1)
		{
			perror("select()");
			exit(errno);
		}
		if (FD_ISSET(STDIN_FILENO, &readfds))
		{
			memset(&buffer, '\0', BUFF_SIZE);
			if ((ret = read(STDIN_FILENO, buffer, BUFF_SIZE)) == -1)
			{
				perror("read");
				goto error;
			}
			buffer[ret] = '\0';
			write_server(sock, buffer, ret);
		}
		else if(FD_ISSET(*sock, &readfds))
		{
			memset(&buffer, '\0', BUFF_SIZE);
			int n = read_server(sock, buffer);
			if (n == 0)
			{
				printf("Server is down !\n");
				goto error;
			}
			if (!strcmp("shutdown", buffer))
			{
				close(*sock);
				write(STDOUT_FILENO, "Server shutdown\n", 16);
				return (0);
			}
			write(STDOUT_FILENO, &buffer, strlen(buffer));
		}
	}
	close(*sock);
	return(0);
error:
	close(*sock);
	return(errno);
}

int	main(void)
{
	SOCKET	sock;

	sock = create_client();
	return (client(&sock));
}
