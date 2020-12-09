#include <linux/types.h>

#include "pxmgr.h"
#include "pxrealm.h"

int pxmgr_init(const char *cdevpath)
{
	int rc;

	rc = pxrealm_init(cdevpath);

	return rc;
}

void pxmgr_exit(void)
{
	pxrealm_exit();
}
