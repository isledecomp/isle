#ifndef MXOMNICREATEPARAM_H
#define MXOMNICREATEPARAM_H

#include "mxomnicreateflags.h"
#include "mxparam.h"
#include "mxstring.h"
#include "mxvideoparam.h"

#include <windows.h>

// VTABLE: LEGO1 0x100dc218
class MxOmniCreateParam : public MxParam {
public:
	__declspec(dllexport) MxOmniCreateParam(
		const char* p_mediaPath,
		struct HWND__* p_windowHandle,
		MxVideoParam& p_vparam,
		MxOmniCreateFlags p_flags
	);

	MxOmniCreateFlags& CreateFlags() { return this->m_createFlags; }
	const MxString& GetMediaPath() const { return m_mediaPath; }
	const HWND GetWindowHandle() const { return m_windowHandle; }
	MxVideoParam& GetVideoParam() { return m_videoParam; }
	const MxVideoParam& GetVideoParam() const { return m_videoParam; }

private:
	MxString m_mediaPath;
	HWND m_windowHandle;
	MxVideoParam m_videoParam;
	MxOmniCreateFlags m_createFlags;
};

// SYNTHETIC: ISLE 0x4014b0
// MxOmniCreateParam::~MxOmniCreateParam

#endif // MXOMNICREATEPARAM_H
