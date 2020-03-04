#include "packer.h"

# define LOADER64_SIZE sizeof(loader64) - 1
static char loader64[] =
"\x57\x56\x50\x51\x52\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\xba"
"\x05\x00\x00\x00\xbe\xb7\x10\x00\x00\x48\x8d\x3d\x5c\x2e\x00\x00"
"\x48\x81\xe7\x00\xf0\xff\xff\xb8\x0a\x00\x00\x00\x0f\x05\xe9\x4a"
"\x2e\x00\x00\xba\x03\x00\x00\x00\xbe\xb7\x10\x00\x00\x48\x8d\x3d"
"\x38\x2e\x00\x00\x48\x81\xe7\x00\xf0\xff\xff\xb8\x0a\x00\x00\x00"
"\x0f\x05\x41\x5c\x41\x5b\x41\x5a\x41\x59\x41\x58\x5a\x59\x58\x5e\x5f";

# define JMP64_SIZE sizeof(jmp64) - 1
static char jmp64[] = "\xe9\xff\xff\xff\xff\xff\xff\xff\xff";

# define WOODY_SIZE sizeof(woody64) - 1
static char woody64[] = 
"\x48\x31\xc0\x48\x31\xdb\x48\x31\xd2\x48\x83\xec\x10\xc7\x04\x24\x2e\x2e\x2e\x2e\xc7\x44\x24\x04\x57\x4f\x4f\x44\xc7\x44\x24\x08\x59\x2e\x2e\x2e\xc7\x44\x24\x0c\x2e\x0a\x00\x00\xba\x0e\x00\x00\x00\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x8d\x34\x24\x90\x90\xc7\x44\x24\x08\x42\x00\x00\x00\xc7\x04\x24\xff\xff\xff\xff\xba\x07\x00\x00\x00\x8b\x34\x24\x48\x81\xc6\x00\x10\x00\x00\x48\x8d\x3d\xf8\xff\xff\xff\x48\x81\xe7\x00\xf0\xff\xff\xb8\x0a\x00\x00\x00\x0f\x05\x41\xb8\xdd\xd3\xb4\x37\x41\xb9\x08\x00\x00\x00\x8b\x54\x24\x08\x8b\x0c\x24\x48\x8d\x3d\x7d\xd1\xff\xff\x8b\x07\x48\x31\xd0\xab\x83\xe9\x04\x83\xf9\x00\x7f\xf2\x44\x01\xc2\x49\xff\xc9\x4d\x85\xc9\x75\xdd\xba\x07\x00\x00\x00\x8b\x34\x24\x48\x81\xc6\x00\x10\x00\x00\x48\x8d\x3d\xf8\xff\xff\xff\x48\x81\xe7\x00\xf0\xff\xff\xb8\x0a\x00\x00\x00\x0f\x05\x48\x83\xc4\x10";

# define JMPEW_SIZE sizeof(jmp_end_woody) - 1
static char jmp_end_woody[] = 
"\xe9\xff\xff\xff\xff";

# define PUSHALL_SIZE sizeof(push_all) - 1
static char push_all[] = 
"\x57\x56\x50\x51\x52\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54";

# define POPALL_SIZE sizeof(pop_all) - 1
static char pop_all[] = 
"\x41\x5c\x41\x5b\x41\x5a\x41\x59\x41\x58\x5a\x59\x58\x5e\x5f";

Elf64_Phdr		*get_last_load64(t_info *info, void *file)
{
	Elf64_Phdr	*program_header;

	if (!(program_header = move_ptr(info, file, sizeof(Elf64_Ehdr))))
		return (0);
	while (program_header->p_type != PT_LOAD)
	{
		if (!(program_header = move_ptr(info, program_header, sizeof(Elf64_Phdr))))
			return (0);
	}
	while (program_header->p_type == PT_LOAD)
	{
		if (!(program_header = move_ptr(info, program_header, sizeof(Elf64_Phdr))))
			return (0);
	}
	program_header--;
	return (program_header);
}

static void		replace_jmp_end_woody64(t_info *info)
{
	// adresse d'arrivee : offset_loader + la moitie (en dur = 0x24)
	// adresse relative : adresse du jump - adresse courante
	// adresse de depart : program_header->p_vaddr + + program_header->p_filesz + WOODY_SIZE - 1

	size_t		depart;
	size_t		arrive;
	uint32_t	rel = 0;

	depart = info->offset_woody_mem + WOODY_SIZE;
	if (info->injection_mode == WOODY_PADDING || info->injection_mode == WOODY_BSS)
		arrive = info->offset_loader_mem + 0x2e;
	else
		arrive = info->base_entry;
	rel = (uint32_t)(arrive - depart);

	ft_memcpy(jmp_end_woody + 1, &(rel), sizeof(uint32_t));
}

static void		modify_woody(t_info *info)
{
	size_t		offset;
	size_t		val;

	offset = info->offset_woody_mem - info->base_entry;

	// put size .text section
	val = info->text_size - 4;
	ft_memcpy(woody64 + 76, &(val), sizeof(uint32_t));

	// put .text begin addr
	val = - 102 - offset;
	ft_memcpy(woody64 + 98, &(val), sizeof(uint32_t));

	// put .text begin addr again
	val = - 142 - offset;
	ft_memcpy(woody64 + 138, &(val), sizeof(uint32_t));

	// put .text begin addr again again
	val = - 189 - offset;
	ft_memcpy(woody64 + 185, &(val), sizeof(uint32_t));

	// put decryption key
	val = get_last_key(info->Key);
	ft_memcpy(woody64 + 69, &(val), sizeof(uint32_t));

}

static void		append_woody64(t_info *info, void *new_file)
{
	if (new_file + info->offset_woody_file + WOODY_SIZE + JMPEW_SIZE >= info->new_file + info->new_file_size)
	{
		info->corruption = 1;
		dprintf(2, "Error, file bad formated\n");
		return ;
	}
	// add .bss section to the physical file : DO nothing, just jump the section

	// edit shellcode with infos
	modify_woody(info);

	// append woody to the end of the .bss
	ft_memcpy(new_file + info->offset_woody_file, woody64, WOODY_SIZE);

	// edit jump shellcode
	replace_jmp_end_woody64(info);

	// append jump to loader to the end of the woody shellcode
	ft_memcpy(new_file + info->offset_woody_file + WOODY_SIZE, jmp_end_woody, JMPEW_SIZE);

}

void			inject_woody64(t_info *info, void *new_file)
{
	if (new_file + WOODY_SIZE + JMPEW_SIZE >= info->new_file + info->new_file_size)
	{
		info->corruption = 1;
		dprintf(2, "Error, file bad formated\n");
		return ;
	}
	// edit shellcode with infos
	modify_woody(info);

	// copy it into file
	ft_memcpy(new_file, woody64, WOODY_SIZE);

	// edit jump shellcode
	replace_jmp_end_woody64(info);

	// append jump to loader to the end of the woody shellcode
	ft_memcpy(new_file + WOODY_SIZE, jmp_end_woody, JMPEW_SIZE);
}

void			append_woody_loader64(t_info *info, void *new_file)
{
	if (new_file + info->offset_woody_file + PUSHALL_SIZE + WOODY_SIZE + POPALL_SIZE + JMPEW_SIZE >= info->new_file + info->new_file_size)
	{
		info->corruption = 1;
		dprintf(2, "Error, file bad formated\n");
		return ;
	}
	info->offset_woody_mem += PUSHALL_SIZE;
	modify_woody(info);
	info->offset_woody_mem -= PUSHALL_SIZE;

// 	info->offset_woody_file += PUSHALL_SIZE;
	ft_memcpy(new_file + info->offset_woody_file, push_all, PUSHALL_SIZE);
	ft_memcpy(new_file + info->offset_woody_file + PUSHALL_SIZE, woody64, WOODY_SIZE);
	ft_memcpy(new_file + info->offset_woody_file + PUSHALL_SIZE + WOODY_SIZE, pop_all, POPALL_SIZE);
// 	info->offset_woody_file -= PUSHALL_SIZE;

	// wrap func
	info->offset_woody_mem += PUSHALL_SIZE + POPALL_SIZE + JMPEW_SIZE;
	replace_jmp_end_woody64(info);
	info->offset_woody_mem -= PUSHALL_SIZE + POPALL_SIZE + JMPEW_SIZE;

// 	info->offset_woody_file += PUSHALL_SIZE + POPALL_SIZE + JMPEW_SIZE;
	ft_memcpy(new_file + info->offset_woody_file + PUSHALL_SIZE + WOODY_SIZE + POPALL_SIZE, jmp_end_woody, JMPEW_SIZE);
// 	info->offset_woody_file -= PUSHALL_SIZE + POPALL_SIZE + JMPEW_SIZE;
}

static void		modify_loader(t_info *info)
{
	uint32_t	new_rel;
	size_t		offset;

	offset = info->offset_woody_mem - info->offset_loader_mem - 1;

	// change first load : offset 31 dans le shellcode
	new_rel = offset - 31;
	ft_memcpy(loader64 + 28, &new_rel, sizeof(uint32_t));

	// change last load: offset 67 dans le shellcode
	new_rel = offset - 67;
	ft_memcpy(loader64 + 64, &new_rel, sizeof(uint32_t));

	// change jmp addr: offset 50 dans le shellcode
	new_rel = offset - 50;
	ft_memcpy(loader64 + 47, &new_rel, sizeof(uint32_t));

}

static int32_t		inject_loader64(t_info *info, void *new_file)
{
	char		*inject;
	uint64_t	addr_to_jmp;

	if (!(inject = malloc(info->loader_size)))
		return (0);

	// calc old entry_point rel addr
	addr_to_jmp = (uint64_t)(info->base_entry - info->offset_loader_mem - info->loader_size + 4);
	ft_memcpy(jmp64 + 1, &(addr_to_jmp), sizeof(uint64_t));

	// modify shellcode_size and rel addr in loader
	modify_loader(info);

	// end injection
	ft_memcpy(inject, loader64, LOADER64_SIZE);
	ft_memcpy(inject + LOADER64_SIZE, jmp64, JMP64_SIZE);
	if (new_file + info->loader_size >= info->new_file + info->new_file_size)
	{
		free(inject);
		info->corruption = 1;
		dprintf(2, "Error, file bad formated\n");
		return (0);
	}
	ft_memcpy(new_file, inject, info->loader_size);
	free(inject);
	return (1);
}

static void			replace_headers64(t_info *info, void *new_file)
{
	Elf64_Ehdr *main_header;
	Elf64_Phdr *program_header;

	// first part : replace_headers for loader
	main_header = (Elf64_Ehdr *)new_file;
	program_header = (Elf64_Phdr *)(new_file + sizeof(Elf64_Ehdr));

	main_header->e_entry = info->offset_loader_mem;
	program_header = (Elf64_Phdr *)(new_file + info->segment_text_header);
	if (info->injection_mode == WOODY_PADDING || info->injection_mode == WOODY_BSS)
	{
		program_header->p_filesz += info->loader_size;
		program_header->p_memsz += info->loader_size;
	}

	// second part : replace_headers for woody
	program_header = (Elf64_Phdr *)(new_file + info->segment_data_header);
	if (info->injection_mode == WOODY_BSS)
	{
		program_header->p_filesz += info->bss_size + info->woody_size;
		program_header->p_memsz = program_header->p_filesz;
	}
	else if (info->injection_mode == WOODY_PADDING)
	{
		program_header->p_filesz += info->woody_size;
		program_header->p_memsz += info->woody_size;
	}
	else if (info->injection_mode == DOUBLE_PADDING)
	{
		program_header->p_filesz += info->woody_size + PUSHALL_SIZE + POPALL_SIZE;
		program_header->p_memsz += info->woody_size + PUSHALL_SIZE + POPALL_SIZE;
		program_header->p_flags |= PF_X;
	}
	else
	{
		main_header->e_entry = program_header->p_vaddr + program_header->p_memsz;
		program_header->p_filesz += info->bss_size + info->woody_size + PUSHALL_SIZE + POPALL_SIZE;
		program_header->p_memsz = program_header->p_filesz;
		program_header->p_flags |= PF_X;
	}
}

static size_t				get_text_size(t_info *info)
{
    Elf64_Phdr  *program_header;

	if (!(program_header = (Elf64_Phdr *)(move_ptr(info, info->file, info->segment_text_header))))
		return (-1);
    return (program_header->p_vaddr + program_header->p_filesz - info->base_entry);
}

static size_t				get_text_segment(t_info *info)
{
	Elf64_Phdr	*header;
	int32_t		i;

	i = 0;
	if (!(header = (Elf64_Phdr *)(move_ptr(info, info->file, sizeof(Elf64_Ehdr)))))
		return (-1);
	while (i < info->nb_hp)
	{
		if ((header->p_type == PT_LOAD) && (info->base_entry > header->p_vaddr) && (info->base_entry < header->p_vaddr + header->p_memsz))
			return ((size_t)header - (size_t)(info->file));

		if (!(header = move_ptr(info, header, sizeof(Elf64_Phdr))))
			return (-1);
		i++;
	}
	dprintf(2, "Error no .text section detected\n");
	return (-1);
}

int32_t				get_elf64_zone(t_info *info)
{
	Elf64_Ehdr *header;
	Elf64_Phdr *program_header;

	header = (Elf64_Ehdr *)(info->file);
	// set functions to 64 bit mode
	info->funcs->inject_loader = &inject_loader64;
	info->funcs->inject_woody = &inject_woody64;
	info->funcs->replace_headers = &replace_headers64;
	info->funcs->replace_jmp_end_woody = &replace_jmp_end_woody64;
	info->funcs->append_woody = &append_woody64;
	info->funcs->append_woody_loader = &append_woody_loader64;
	info->funcs->encryption = &encryption64;

	if (!(program_header = get_last_load64(info, info->file)))
		return (1);
	// save usefull infos
	info->nb_hp = header->e_phnum;
	info->base_entry = header->e_entry;
	if ((info->segment_text_header = get_text_segment(info)) == (size_t)(-1))
		return (1);
	if ((info->text_size = get_text_size(info)) == (size_t)(-1))
		return (1);
	info->bss_size = program_header->p_memsz - program_header->p_filesz;
	info->end_data_seg = program_header->p_offset + program_header->p_filesz;
	info->loader_size = LOADER64_SIZE + JMP64_SIZE;
	info->woody_size = WOODY_SIZE + JMPEW_SIZE;
	info->push_size = PUSHALL_SIZE;

	if (get_case64_1(info) == 0)
	{
		info->injection_mode = WOODY_PADDING;
		return (0);
	}
	if (get_case64_2(info) == 0)
	{
	info->injection_mode = WOODY_BSS;
		return (0);
	}
	if (get_case64_3(info) == 0)
	{
		info->injection_mode = DOUBLE_PADDING;
		return (0);
	}
	if (get_case64_4(info) == 0)
	{
		info->injection_mode = DOUBLE_BSS;
		return (0);
	}
	return (1);
}
