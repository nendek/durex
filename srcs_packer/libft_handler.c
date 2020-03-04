#include "packer.h"

void	ft_memcpy(void *dest, void *src, size_t size)
{
	size_t i = 0;

	while (i < size)
	{
		((char *)dest)[i] = ((char *)src)[i];
		i++;
	}
}

void	ft_memcpy_p(void *dest, void *src, size_t size, t_info *info)
{
	size_t i = 0;

	while (i < size)
	{
		if ((dest + i >= info->new_file + info->new_file_size) || (src + i >= info->file + info->file_size))
		{
			info->corruption = 1;
			dprintf(2, "Error, file bad formated\n");
			return ;
		}
		if ((dest + i < info->new_file) || (src + i < info->file))
		{
			info->corruption = 1;
			dprintf(2, "Error, file bad formated\n");
			return ;
		}
		((char *)dest)[i] = ((char *)src)[i];
		i++;
	}
}

void		ft_bzero(char *str, size_t len)
{
	size_t		i;

	i = 0;
	while (i < len)
		str[i++] = '\0';
}

void		*move_ptr(t_info *info, void *ptr, size_t to_add)
{
	if ((size_t)ptr + to_add >= (size_t)(info->file + info->file_size))
	{
		info->corruption = 1;
		dprintf(2, "Error, file bad formated\n");
		return (NULL);
	}
	return ((void *)((size_t)ptr + to_add));
}

static  int		ft_iswp(char c)
{
	if (c == ' ' || c == '\t' || c == '\n' \
			|| c == '\r' || c == '\v' || c == '\f')
		return (1);
	return (0);
}

static int		ft_isdigit(int c)
{
	if (c >= '0' && c <= '9')
		return (1);
	else
		return (0);
}

static int	sign(int *i, const char *str)
{
	if (str[*i] == '-')
	{
		*i = *i + 1;
		return (-1);
	}
	if (str[*i] == '+')
		*i = *i + 1;
	return (1);
}

uint32_t	ft_atoi(char *str)
{
	int		i;
	int		res;
	int		s;

	i = 0;
	res = 0;
	while (str[i] != '\0' && ft_iswp(str[i]) == 1)
		i++;
	s = sign(&i, str);
	while (str[i] != '\0')
	{
		if (ft_isdigit(str[i]) != 1)
			return ((uint32_t)(res * s));
		res = res * 10 + str[i] - '0';
		i++;
	}
	return ((uint32_t)(res * s));
}
