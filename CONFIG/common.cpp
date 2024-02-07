#include "common.h"

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
