#if !defined(AFX_CONFIGCOMMANDLINEINFO_H)
#define AFX_CONFIGCOMMANDLINEINFO_H

#include "compat.h"
#include "config.h"
#include "decomp.h"

#include <afxwin.h>

// VTABLE CONFIG 0x004060e8
// SIZE 0x24
class CConfigCommandLineInfo : public CCommandLineInfo {
public:
	CConfigCommandLineInfo();

	void ParseParam(LPCSTR pszParam, BOOL bFlag, BOOL bLast) override;
};

#endif // !defined(AFX_CONFIGCOMMANDLINEINFO_H)
