#ifndef MXVIDEOPARAM_H
#define MXVIDEOPARAM_H

#include "compat.h"
#include "mxpalette.h"
#include "mxrect32.h"
#include "mxtypes.h"
#include "mxvariabletable.h"
#include "mxvideoparamflags.h"

#include <ddraw.h>

// SIZE 0x24
class MxVideoParam {
public:
	MxVideoParam();
	MxVideoParam(MxVideoParam& p_videoParam);
	__declspec(dllexport)
		MxVideoParam(MxRect32& p_rect, MxPalette* p_palette, MxULong p_backBuffers, MxVideoParamFlags& p_flags);
	MxVideoParam& operator=(const MxVideoParam& p_videoParam);
	~MxVideoParam();
	void SetDeviceName(char* p_deviceId);

	inline MxVideoParamFlags& Flags() { return m_flags; }

	inline void SetPalette(MxPalette* p_palette) { this->m_palette = p_palette; }
	inline void SetBackBuffers(MxU32 p_backBuffers) { this->m_backBuffers = p_backBuffers; }

	inline MxRect32& GetRect() { return this->m_rect; }
	inline MxPalette* GetPalette() { return this->m_palette; }
	inline MxU32 GetBackBuffers() { return this->m_backBuffers; }
	inline char* GetDeviceName() { return this->m_deviceId; }

private:
	MxRect32 m_rect;           // 0x00
	MxPalette* m_palette;      // 0x10
	MxU32 m_backBuffers;       // 0x14
	MxVideoParamFlags m_flags; // 0x18
	int m_unk0x1c;             // 0x1c
	char* m_deviceId;          // 0x20
};

#endif // MXVIDEOPARAM_H
