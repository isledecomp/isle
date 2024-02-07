#ifndef AFX_COMMON_H
#define AFX_COMMON_H

#include <afxwin.h>

#include "compat.h"

class CSerializer {
public:
    void Serialize(CArchive& ar);
    void AssertValid() const;
    void Dump(CDumpContext& dc) const;
};

class CCommonDialog : public CDialog {
public:
    CCommonDialog(UINT nIDTemplate, CWnd* pParentWnd = NULL) : CDialog(nIDTemplate, pParentWnd) { }

    void BeginModalState() override;
    void EndModalState() override;
};

#endif
