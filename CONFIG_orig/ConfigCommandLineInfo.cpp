#include "ConfigCommandLineInfo.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(CCommandLineInfo, 0x24)
DECOMP_SIZE_ASSERT(CConfigCommandLineInfo, 0x24)

// FUNCTION: CONFIG 0x00403b10
CConfigCommandLineInfo::CConfigCommandLineInfo()
{
	currentConfigApp->m_run_config_dialog = FALSE;
}

// FUNCTION: CONFIG 0x00403bf0
void CConfigCommandLineInfo::ParseParam(LPCSTR pszParam, BOOL bFlag, BOOL bLast)
{
	if (bFlag) {
		if (lstrcmpiA(pszParam, "config") == 0) {
			currentConfigApp->m_run_config_dialog = TRUE;
		}
	}
}
