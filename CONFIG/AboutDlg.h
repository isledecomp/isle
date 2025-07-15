#if !defined(AFX_ABOUTDLG_H)
#define AFX_ABOUTDLG_H

#include "StdAfx.h"
#include "compat.h"
#include "res/resource.h"

// VTABLE: CONFIG 0x00406308
// VTABLE: CONFIGD 0x0040c3f8
// SIZE 0x60
class CAboutDialog : public CDialog {
public:
	CAboutDialog();
	enum {
		IDD = IDD_ABOUT
	};

protected:
	void DoDataExchange(CDataExchange* pDX) override;

protected:
	DECLARE_MESSAGE_MAP()
};

// SYNTHETIC: CONFIG 0x00403cb0
// SYNTHETIC: CONFIGD 0x00409840
// CAboutDialog::`scalar deleting destructor'

// SYNTHETIC: CONFIG 0x00404100
// SYNTHETIC: CONFIGD 0x00409890
// CAboutDialog::~CAboutDialog

// FUNCTION: CONFIG 0x00403d30
// FUNCTION: CONFIGD 0x004086c7
// CAboutDialog::_GetBaseMessageMap

// FUNCTION: CONFIG 0x00403d40
// FUNCTION: CONFIGD 0x004086dc
// CAboutDialog::GetMessageMap

// GLOBAL: CONFIG 0x00406100
// GLOBAL: CONFIGD 0x0040c188
// CAboutDialog::messageMap

// GLOBAL: CONFIG 0x00406108
// GLOBAL: CONFIGD 0x0040c190
// CAboutDialog::_messageEntries

#endif // !defined(AFX_ABOUTDLG_H)
