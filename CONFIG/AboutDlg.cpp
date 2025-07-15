#include "AboutDlg.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(CDialog, 0x60)
DECOMP_SIZE_ASSERT(CAboutDialog, 0x60)

// FUNCTION: CONFIG 0x00403c20
// FUNCTION: CONFIGD 0x00408630
CAboutDialog::CAboutDialog() : CDialog(IDD)
{
}

// FUNCTION: CONFIG 0x00403d20
// FUNCTION: CONFIGD 0x004086a3
void CAboutDialog::DoDataExchange(CDataExchange* pDX)
{
	CWnd::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDialog, CDialog)
END_MESSAGE_MAP()
