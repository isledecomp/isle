#if !defined(AFX_ABOUTDLG_H)
#define AFX_ABOUTDLG_H

#include "StdAfx.h"
#include "compat.h"
#include "res/resource.h"

// VTABLE: CONFIG 0x00406308
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
// CAboutDialog::`scalar deleting destructor'

// FUNCTION: CONFIG 0x00403d40
// CAboutDialog::GetMessageMap

// GLOBAL: CONFIG 0x00406100
// CAboutDialog::messageMap

// GLOBAL: CONFIG 0x00406108
// CAboutDialog::_messageEntries

#endif // !defined(AFX_ABOUTDLG_H)
