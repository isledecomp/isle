#if !defined(AFX_CONFIGCOMMANDLINEINFO_H)
#define AFX_CONFIGCOMMANDLINEINFO_H

#include "StdAfx.h"
#include "compat.h"
#include "config.h"
#include "decomp.h"

// VTABLE: CONFIG 0x004060e8
// SIZE 0x24
class CConfigCommandLineInfo : public CCommandLineInfo {
public:
	CConfigCommandLineInfo();

	void ParseParam(LPCSTR pszParam, BOOL bFlag, BOOL bLast) override;
};

// SYNTHETIC: CONFIG 0x00403b80
// CConfigCommandLineInfo::`scalar deleting destructor'

#endif // !defined(AFX_CONFIGCOMMANDLINEINFO_H)
