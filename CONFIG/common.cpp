#include "common.h"


// FUNCTION: CONFIG 0x00402ca0
void CSerializer::Serialize(CArchive& ar) {
}

// FUNCTION: CONFIG 0x00402cb0
void CSerializer::AssertValid() const {
}

// FUNCTION: CONFIG 0x00402cc0
void CSerializer::Dump(CDumpContext& dc) const {
}

// FUNCTION: CONFIG 0x00403c90
void CCommonDialog::BeginModalState()
{
    ::EnableWindow(m_hWnd, FALSE);
}

// FUNCTION: CONFIG 0x00403ca0
void CCommonDialog::EndModalState()
{
    ::EnableWindow(m_hWnd, TRUE);
}
