#include "mxomnicreateparam.h"

// FUNCTION: LEGO1 0x100b0b00
MxOmniCreateParam::MxOmniCreateParam(
	const char* p_mediaPath,
	struct HWND__* p_windowHandle,
	MxVideoParam& p_vparam,
	MxOmniCreateFlags p_flags
)
{
	this->m_mediaPath = p_mediaPath;
	this->m_windowHandle = (HWND) p_windowHandle;
	this->m_videoParam = p_vparam;
	this->m_createFlags = p_flags;
}
