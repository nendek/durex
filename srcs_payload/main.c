#include "payload.h"

int			g_fd;
int			g_sock;

static void		sig_handler(const int signo)
{
	(void)signo;
	if (g_fd != 0)
		unlock_deamon(&g_fd);
	if (g_sock != 0)
		close(g_sock);
	exit(EXIT_SUCCESS);
}

static void		sigsig(void)
{
	signal(SIGTSTP, SIG_IGN);
	signal(SIGCONT, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGCHLD, SIG_DFL);
	signal(SIGTERM, sig_handler);
	signal(SIGINT, sig_handler);
	signal(SIGQUIT, sig_handler);
}

int			main(void)
{
	pid_t			pid;
	pid_t			sid;
	int			fd;
	int			sock;

	g_fd = 0;
	g_sock = 0;
	fd = 0;
	if ((check_credentials()) != 0)
		return (EXIT_FAILURE);
	if ((lock_daemon(&fd)) != 0)
		return (EXIT_FAILURE);
	g_fd = fd;
	pid = fork();
	if (pid < 0)
		goto error;
	if (pid == 0)
	{
		sigsig();
		umask(0);
		sid = setsid();
		if (sid < 0)
			goto error;
		if ((chdir("/") < 0))
			goto error;
		//close(STDIN_FILENO);
		//close(STDOUT_FILENO);
		//close(STDERR_FILENO);
		if ((sock = create_server()) < 0)
			goto error;
		g_sock = sock;
		run_server(&sock);
		unlock_deamon(&fd);
	}
	return (EXIT_SUCCESS);
error:
	close(sock);
	unlock_deamon(&fd);
	return (EXIT_FAILURE);
}
