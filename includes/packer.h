#ifndef WOODY_H
# define WOODY_H

# include <sys/mman.h>
# include <sys/time.h>
# include <elf.h>
# include <fcntl.h>
# include <sys/stat.h>
# include <unistd.h>
# include <stdlib.h>
# include <stdio.h>
# include <time.h>

# define ELF_32 1
# define ELF_64 2
# define WOODY_PADDING 1
# define WOODY_BSS 2
# define DOUBLE_PADDING 3
# define DOUBLE_BSS 4
# define NB_TIMING 8
# define TIMING 0x37B4D3DD

typedef struct			s_MEgA_StRuCtuRrRE_HAXOR t_info;

typedef struct			s_funcs
{
	int32_t		(*inject_loader)(t_info *, void *);
	void		(*replace_headers)(t_info *, void *);
	void		(*append_woody)(t_info *, void *);
	void		(*inject_woody)(t_info *, void *);
	void		(*append_woody_loader)(t_info *, void *);
	void		(*replace_jmp_end_woody)(t_info *);
	void		(*encryption)(t_info *, void *);
}						t_funcs;

struct				s_MEgA_StRuCtuRrRE_HAXOR
{
	void			*file;
	size_t			file_size;
	void			*new_file;
	size_t			new_file_size;
	int				injection_mode;
	int				corruption;

	// base file info
	int32_t			nb_hp;
	size_t			base_entry;
	size_t			text_size;
	size_t			bss_size;
	size_t			end_data_seg;
	size_t			segment_text_header;
	size_t			segment_data_header;

	// packer file info
	size_t			offset_loader_file;
	size_t			offset_loader_mem;
	size_t			loader_size;
	size_t			offset_woody_file;
	size_t			offset_woody_mem;
	size_t			woody_size;
	size_t			push_size;
	uint32_t		Key;
	t_funcs			*funcs;

};
		/* parsing_files */
int32_t		get_elf64_zone(t_info *info);
Elf64_Phdr  *get_last_load64(t_info *info, void *file);
int32_t		get_case64_1(t_info *info);
int32_t		get_case64_2(t_info *info);
int32_t		get_case64_3(t_info *info);
int32_t		get_case64_4(t_info *info);

		/* injection handler */
void		create_woody(t_info *info);
void		inject_woody(t_info *info, void *new_file);
void		append_woody_loader(t_info *info, void *new_file);


		/* CRYPTO HANDLER */
void		get_Key(t_info *info, char *str);
void		create_Key(t_info *info);
uint32_t	get_last_key(uint32_t master_Key);
void		encryption64(t_info *info, void *file);


		/* LIBFT_HANDLER */
void		ft_memcpy(void *dest, void *src, size_t size);
void		ft_memcpy_p(void *dest, void *src, size_t size, t_info *info);
void		ft_bzero(char *str, size_t len);
uint32_t	ft_atoi(char *str);
void		*move_ptr(t_info *info, void *ptr, size_t to_add);

#endif
