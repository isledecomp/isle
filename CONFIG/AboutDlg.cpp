#include "AboutDlg.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(CAboutDialog, 0x60)

// FUNCTION: CONFIG 0x00403c20
CAboutDialog::CAboutDialog() : CDialog(IDD)
{
}

// FUNCTION: CONFIG 0x00403c90
void CAboutDialog::BeginModalState()
{
	::EnableWindow(this->m_hWnd, FALSE);
}

// FUNCTION: CONFIG 0x00403ca0
void CAboutDialog::EndModalState()
{
	::EnableWindow(this->m_hWnd, TRUE);
}

// FUNCTION: CONFIG 0x00403d20
void CAboutDialog::DoDataExchange(CDataExchange* pDX)
{
}

// FIXME: are these tags correct?
// FIXME: how to tag static in-method variables?

// FUNCTION CAboutDialog::GetMessageMap: CONFIG 0x00403d50
// GLOBAL CAboutDialog::GetThisMessageMap()::messageMap CONFIG 0x00406100
// GLOBAL CAboutDialog::GetThisMessageMap()::_messageEntries CONFIG 0x00406108

BEGIN_MESSAGE_MAP(CAboutDialog, CDialog)
END_MESSAGE_MAP()
