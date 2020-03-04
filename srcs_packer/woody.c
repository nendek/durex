#include "packer.h"

int32_t	get_type(void *file)
{
	uint32_t			magic;
	Elf64_Ehdr			*elf;

	magic = *(uint32_t *)file;
	if (magic == 0x464C457F)
	{
		elf = (Elf64_Ehdr *)file;
		if (elf->e_type != 2 && elf->e_type != 3)
		{
			dprintf(2, "ERROR, file is not an EXEC\n");
			return (0);
		}
		if (elf->e_machine == 0x3e)
			return (ELF_64);
		dprintf(2, "ERROR in Elf_header\n");
	}
	dprintf(2, "ERROR file is not ELF\n");
	return (0);
}

int32_t	get_vulnerable_zone(t_info *info, int32_t type)
{
	if (type == ELF_64)
		return (get_elf64_zone(info));
	return (1);
}

static t_info	*init_info()
{
	t_info *ret;

	if (!(ret = malloc(sizeof(t_info))))
		return (NULL);
	if (!(ret->funcs = malloc(sizeof(t_funcs))))
	{
		free(ret);
		return (NULL);
	}

	ret->file = NULL;
	ret->corruption = 0;
	return (ret);
}

int		main(int argc, char **argv)
{
	t_info			*info;
	struct stat		buf;
	int32_t			fd;

	if (argc != 2 && argc != 3)
	{
		dprintf(1, "usage: ./woody_woodpacker file [key]\n");
		return (EXIT_FAILURE);
	}
	if ((fd = open(argv[1], O_RDONLY)) < 0)
		return (EXIT_FAILURE);
	if (fstat(fd, &buf) < 0)
	{
		close(fd);
		return (EXIT_FAILURE);
	}
	if (!(info = init_info()))
		return (0);
	if ((info->file = mmap(0, (size_t)buf.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
	{
		free(info->funcs);
		free(info);
		return (EXIT_FAILURE);
	}
	info->file_size = (size_t)buf.st_size;
	if (get_vulnerable_zone(info, get_type(info->file)) == 1)
	{
		free(info->funcs);
		free(info);
		return (EXIT_FAILURE);
	}
	if (argc == 2)
		create_Key(info);
	else
		get_Key(info, argv[2]);
	create_woody(info);
	if (info->corruption == 0)
		dprintf(1, "Encryption Key : %#x\n", info->Key);
	free(info->funcs);
	free(info);
	return (0);
}
