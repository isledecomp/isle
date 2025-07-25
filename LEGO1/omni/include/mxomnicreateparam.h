#ifndef MXOMNICREATEPARAM_H
#define MXOMNICREATEPARAM_H

#include "mxomnicreateflags.h"
#include "mxparam.h"
#include "mxstring.h"
#include "mxvideoparam.h"

#include <windows.h>

// VTABLE: LEGO1 0x100dc218
// VTABLE: BETA10 0x101c1ca8
class MxOmniCreateParam : public MxParam {
public:
	MxOmniCreateParam(
		const char* p_mediaPath,
		struct HWND__* p_windowHandle,
		MxVideoParam& p_vparam,
		MxOmniCreateFlags p_flags
	);

	// FUNCTION: BETA10 0x10092cb0
	MxOmniCreateFlags& CreateFlags() { return this->m_createFlags; }

	const MxString& GetMediaPath() const { return m_mediaPath; }

	// FUNCTION: BETA10 0x10092c50
	const HWND GetWindowHandle() const { return m_windowHandle; }

	// FUNCTION: BETA10 0x10092c80
	MxVideoParam& GetVideoParam() { return m_videoParam; }

	const MxVideoParam& GetVideoParam() const { return m_videoParam; }

	// SYNTHETIC: LEGO1 0x100b0a70
	// SYNTHETIC: BETA10 0x10132740
	// MxOmniCreateParam::`scalar deleting destructor'

private:
	MxString m_mediaPath;            // 0x04
	HWND m_windowHandle;             // 0x14
	MxVideoParam m_videoParam;       // 0x18
	MxOmniCreateFlags m_createFlags; // 0x3c
};

// SYNTHETIC: ISLE 0x4014b0
// SYNTHETIC: BETA10 0x10132780
// MxOmniCreateParam::~MxOmniCreateParam

#endif // MXOMNICREATEPARAM_H
