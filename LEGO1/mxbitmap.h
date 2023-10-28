#ifndef MXBITMAP_H
#define MXBITMAP_H

#include "mxcore.h"
#include "mxpalette.h"
#include "mxtypes.h"

#include <stdlib.h>

// The stock BITMAPINFO struct from wingdi.h only makes room for one color
// in the palette. It seems like the expectation (if you use the struct)
// is to malloc as much as you actually need, and then index into the array
// anyway even though its stated size is [1].
// https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapinfo
// In our case, the size 0x428 is used frequently, which matches
// a 40-byte header plus 256 colors, so just use that as our template.

// SIZE 0x428
struct MxBITMAPINFO {
	BITMAPINFOHEADER bmiHeader;
	RGBQUAD bmiColors[256];
};

// Non-standard value for biCompression in the BITMAPINFOHEADER struct.
// By default, uncompressed bitmaps (BI_RGB) are stored in bottom-up order.
// You can specify that the bitmap has top-down order instead by providing
// a negative number for biHeight. It could be that Mindscape decided on a
// belt & suspenders approach here.
#define BI_RGB_TOPDOWN 0x10

// SIZE 0x20
// VTABLE 0x100dc7b0
class MxBitmap : public MxCore {
public:
	__declspec(dllexport) MxBitmap();
	__declspec(dllexport) virtual ~MxBitmap(); // vtable+00

	virtual MxResult ImportBitmap(MxBitmap* p_bitmap);                                     // vtable+14
	virtual MxResult ImportBitmapInfo(MxBITMAPINFO* p_info);                               // vtable+18
	virtual MxResult SetSize(MxS32 p_width, MxS32 p_height, MxPalette* p_palette, MxBool); // vtable+1c
	virtual MxResult LoadFile(HANDLE p_handle);                                            // vtable+20
	__declspec(dllexport) virtual MxLong Read(const char* p_filename);                     // vtable+24
	virtual int vtable28(int);
	virtual void vtable2c(int, int, int, int, int, int, int);
	virtual void vtable30(int, int, int, int, int, int, int);
	__declspec(dllexport) virtual MxPalette* CreatePalette(); // vtable+34
	virtual void ImportPalette(MxPalette* p_palette);         // vtable+38
	virtual MxResult SetBitDepth(MxBool);                     // vtable+3c
	virtual MxResult StretchBits(
		HDC p_hdc,
		MxS32 p_xSrc,
		MxS32 p_ySrc,
		MxS32 p_xDest,
		MxS32 p_yDest,
		MxS32 p_destWidth,
		MxS32 p_destHeight
	); // vtable+40

	inline BITMAPINFOHEADER* GetBmiHeader() const { return m_bmiHeader; }
	inline MxLong GetBmiWidth() const { return m_bmiHeader->biWidth; }
	inline MxLong GetBmiStride() const { return ((m_bmiHeader->biWidth + 3) & -4); }
	inline MxLong GetBmiHeight() const { return m_bmiHeader->biHeight; }
	inline MxLong GetBmiHeightAbs() const
	{
		return m_bmiHeader->biHeight > 0 ? m_bmiHeader->biHeight : -m_bmiHeader->biHeight;
	}
	inline MxU8* GetBitmapData() const { return m_data; }

private:
	MxResult ImportColorsToPalette(RGBQUAD*, MxPalette*);

	MxBITMAPINFO* m_info;          // 0x8
	BITMAPINFOHEADER* m_bmiHeader; // 0xc
	RGBQUAD* m_paletteData;        // 0x10
	MxU8* m_data;                  // 0x14
	MxBool m_isHighColor;          // 0x18
	MxPalette* m_palette;          // 0x1c
};

#endif // MXBITMAP_H
