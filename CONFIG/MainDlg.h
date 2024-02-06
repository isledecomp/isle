#if !defined(AFX_MAINDLG_H)
#define AFX_MAINDLG_H

#include "afxwin.h"
#include "compat.h"
#include "decomp.h"
#include "res/resource.h"

// VTABLE: CONFIG 0x004063e0
// SIZE 0x70
class CMainDialog : public CDialog {
public:
	CMainDialog(CWnd* pParent);
	// Dialog Data
	//{{AFX_DATA(CMainDialog)
	enum {
		IDD = IDD_MAIN
	};
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CMainDialog)

protected:
	void DoDataExchange(CDataExchange* pDX) override;
	void BeginModalState() override {}
	void EndModalState() override {}
	//}}AFX_VIRTUAL
	void UpdateInterface();
	void SwitchToAdvanced(BOOL p_advanced);

	undefined m_unk0x60[4]; // 0x60
	HCURSOR m_icon;         // 0x64
	BOOL m_modified;        // 0x68
	BOOL m_advanced;        // 0x6c
							// Implementation

protected:
	//{{AFX_MSG(CMainDialog)
	BOOL OnInitDialog() override;
	void OnSysCommand(UINT nID, LPARAM lParam);
	void OnPaint();
	HCURSOR OnQueryDragIcon();
	void OnList3DevicesSelectionChanged();
	void OnCancel();
	void OnDestroy();
	void OnButtonCancel();
	void OnCheckbox3DSound();
	void OnCheckbox3DVideoMemory();
	void OnRadiobuttonPalette16bit();
	void OnRadiobuttonPalette256();
	void OnCheckboxFlipVideoMemPages();
	void OnRadiobuttonModelLowQuality();
	void OnRadiobuttonModelHighQuality();
	void OnRadiobuttonTextureLowQuality();
	void OnRadiobuttonTextureHighQuality();
	void OnCheckboxJoystick();
	void OnButtonAdvanced();
	void OnCheckboxDrawCursor();
	void OnCheckboxMusic();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

// FUNCTION: CONFIG 0x00403e70
// CMainDialog::GetMessageMap

// GLOBAL: CONFIG 0x00406120
// CMainDialog::messageMap

// GLOBAL: CONFIG 0x00406128
// CMainDialog::_messageEntries


#endif // !defined(AFX_MAINDLG_H)
