#include "durex.h"

int		check_credentials(void)
{
	uid_t cred;

	if ((cred = geteuid()) == 0)
		return (0);
	return (1);
}
