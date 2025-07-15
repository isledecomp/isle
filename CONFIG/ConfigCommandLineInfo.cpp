#include "ConfigCommandLineInfo.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(CCommandLineInfo, 0x24)
DECOMP_SIZE_ASSERT(CConfigCommandLineInfo, 0x24)

// FUNCTION: CONFIG 0x00403b10
// FUNCTION: CONFIGD 0x00407caa
CConfigCommandLineInfo::CConfigCommandLineInfo()
{
	currentConfigApp->m_run_config_dialog = FALSE;
}

// FUNCTION: CONFIG 0x00403ba0
// FUNCTION: CONFIGD 0x00407d2e
CConfigCommandLineInfo::~CConfigCommandLineInfo()
{
}

// FUNCTION: CONFIG 0x00403bf0
// FUNCTION: CONFIGD 0x00407d96
void CConfigCommandLineInfo::ParseParam(LPCSTR pszParam, BOOL bFlag, BOOL bLast)
{
	if (bFlag) {
		if (lstrcmpi(pszParam, "config") == 0) {
			currentConfigApp->m_run_config_dialog = TRUE;
		}
	}
}
