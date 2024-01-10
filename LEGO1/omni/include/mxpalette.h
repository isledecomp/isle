#ifndef MXPALETTE_H
#define MXPALETTE_H

#include "mxcore.h"
#include "mxtypes.h"

#include <ddraw.h>

// VTABLE: LEGO1 0x100dc848
// SIZE 0x414
class MxPalette : public MxCore {
public:
	__declspec(dllexport) MxBool operator==(MxPalette& p_other);
	__declspec(dllexport) void Detach();

	MxPalette();
	MxPalette(const RGBQUAD*);
	virtual ~MxPalette();

	void ApplySystemEntriesToPalette(LPPALETTEENTRY p_entries);
	MxPalette* Clone();
	void GetDefaultPalette(LPPALETTEENTRY p_entries);
	MxResult GetEntries(LPPALETTEENTRY p_entries);
	MxResult SetEntries(LPPALETTEENTRY p_palette);
	MxResult SetSkyColor(LPPALETTEENTRY p_skyColor);
	void Reset(MxBool p_ignoreSkyColor);
	LPDIRECTDRAWPALETTE CreateNativePalette();

	inline void SetOverrideSkyColor(MxBool p_value) { this->m_overrideSkyColor = p_value; }

private:
	LPDIRECTDRAWPALETTE m_palette;
	PALETTEENTRY m_entries[256]; // 0xc
	MxBool m_overrideSkyColor;   // 0x40c
	PALETTEENTRY m_skyColor;     // 0x40d
};

#endif // MXPALETTE_H
