#ifndef AFX_COMMON_H
#define AFX_COMMON_H

#include "compat.h"

#include <afxwin.h>

class CCommonDialog : public CDialog {
public:
	CCommonDialog(UINT nIDTemplate, CWnd* pParentWnd = NULL) : CDialog(nIDTemplate, pParentWnd) {}

	void BeginModalState() override;
	void EndModalState() override;
};

#endif
