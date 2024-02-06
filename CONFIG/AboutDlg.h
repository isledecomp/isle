#if !defined(AFX_ABOUTDLG_H)
#define AFX_ABOUTDLG_H

#include "afxwin.h"
#include "compat.h"
#include "res/resource.h"

// VTABLE: CONFIG 0x00406308
// SIZE 0x60
class CAboutDialog : public CDialog {
public:
	CAboutDialog();
	// Dialog Data
	//{{AFX_DATA(CMainDialog)
	enum {
		IDD = IDD_ABOUT
	};
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CMainDialog)

protected:
	void DoDataExchange(CDataExchange* pDX) override;
	void BeginModalState() override;
	void EndModalState() override;
	//}}AFX_VIRTUAL
	//    void UpdateInterface();
	//    void SwitchToAdvanced(BOOL p_advanced);
	// Implementation

protected:
	//{{AFX_MSG(CMainDialog)
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

// FUNCTION: CONFIG 0x00403d40
// CAboutDialog::GetMessageMap

// GLOBAL: CONFIG 0x00406100
// CAboutDialog::messageMap

// GLOBAL: CONFIG 0x00406108
// CAboutDialog::_messageEntries

#endif // !defined(AFX_ABOUTDLG_H)
