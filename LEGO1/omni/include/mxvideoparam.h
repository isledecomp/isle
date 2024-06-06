#ifndef MXVIDEOPARAM_H
#define MXVIDEOPARAM_H

#include "compat.h"
#include "mxrect32.h"
#include "mxtypes.h"
#include "mxvideoparamflags.h"

#include <ddraw.h>

class MxPalette;

// SIZE 0x24
class MxVideoParam {
public:
	MxVideoParam();
	__declspec(dllexport)
		MxVideoParam(MxRect32& p_rect, MxPalette* p_palette, MxULong p_backBuffers, MxVideoParamFlags& p_flags);
	MxVideoParam(MxVideoParam& p_videoParam);
	~MxVideoParam();
	void SetDeviceName(char* p_deviceId);
	MxVideoParam& operator=(const MxVideoParam& p_videoParam);

	// FUNCTION: BETA10 0x100886e0
	inline MxVideoParamFlags& Flags() { return m_flags; }

	// FUNCTION: BETA10 0x100d81f0
	inline MxRect32& GetRect() { return m_rect; }

	// FUNCTION: BETA10 0x100d8210
	inline MxPalette* GetPalette() { return m_palette; }

	// FUNCTION: BETA10 0x100d8240
	inline void SetPalette(MxPalette* p_palette) { m_palette = p_palette; }

	// FUNCTION: BETA10 0x100d8270
	inline char* GetDeviceName() { return m_deviceId; }

	// FUNCTION: BETA10 0x10141f60
	inline MxU32 GetBackBuffers() { return m_backBuffers; }

	// FUNCTION: BETA10 0x10141fe0
	inline void SetBackBuffers(MxU32 p_backBuffers) { m_backBuffers = p_backBuffers; }

private:
	MxRect32 m_rect;           // 0x00
	MxPalette* m_palette;      // 0x10
	MxU32 m_backBuffers;       // 0x14
	MxVideoParamFlags m_flags; // 0x18
	int m_unk0x1c;             // 0x1c
	char* m_deviceId;          // 0x20
};

#endif // MXVIDEOPARAM_H
