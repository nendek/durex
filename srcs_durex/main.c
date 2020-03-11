#include "durex.h"

#include <stdio.h>

int get_info(struct stat *st, char *path)
{

}

int main(int argc, char **argv)
{
	struct stat	st;
	int		in_durex;

	(void)argc;
	in_durex = 1;
	if (in_durex)
	{
		write(STDIN_FILENO, "pnardozi\n", 9); 
	}
	else
	{
	}
	return (0);
}
