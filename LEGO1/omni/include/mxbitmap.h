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
	BITMAPINFOHEADER m_bmiHeader;
	RGBQUAD m_bmiColors[256];

	static MxU32 Size() { return sizeof(MxBITMAPINFO); }
};

// Non-standard value for biCompression in the BITMAPINFOHEADER struct.
// By default, uncompressed bitmaps (BI_RGB) are stored in bottom-up order.
// You can specify that the bitmap has top-down order instead by providing
// a negative number for biHeight. It could be that Mindscape decided on a
// belt & suspenders approach here.
#define BI_RGB_TOPDOWN 0x10

// SIZE 0x20
// VTABLE: LEGO1 0x100dc7b0
class MxBitmap : public MxCore {
public:
	__declspec(dllexport) MxBitmap();
	__declspec(dllexport) virtual ~MxBitmap(); // vtable+00

	virtual MxResult ImportBitmap(MxBitmap* p_bitmap);                                     // vtable+14
	virtual MxResult ImportBitmapInfo(MxBITMAPINFO* p_info);                               // vtable+18
	virtual MxResult SetSize(MxS32 p_width, MxS32 p_height, MxPalette* p_palette, MxBool); // vtable+1c
	virtual MxResult LoadFile(HANDLE p_handle);                                            // vtable+20
	__declspec(dllexport) virtual MxLong Read(const char* p_filename);                     // vtable+24

	// FUNCTION: LEGO1 0x1004e0d0
	virtual int VTable0x28(int) { return -1; }; // vtable+28

	virtual void BitBlt(
		MxBitmap* p_src,
		MxS32 p_left,
		MxS32 p_top,
		MxS32 p_right,
		MxS32 p_bottom,
		MxS32 p_width,
		MxS32 p_height
	); // vtable+2c
	virtual void BitBltTransparent(
		MxBitmap* p_src,
		MxS32 p_left,
		MxS32 p_top,
		MxS32 p_right,
		MxS32 p_bottom,
		MxS32 p_width,
		MxS32 p_height
	);                                                        // vtable+30
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

	// Bit mask trick to round up to the nearest multiple of four.
	// Pixel data may be stored with padding.
	// https://learn.microsoft.com/en-us/windows/win32/medfound/image-stride
	inline MxLong AlignToFourByte(MxLong p_value) const { return (p_value + 3) & -4; }

	// Same as the one from legoutil.h, but flipped the other way
	// TODO: While it's not outside the realm of possibility that they
	// reimplemented Abs for only this file, that seems odd, right?
	inline MxLong AbsFlipped(MxLong p_value) const { return p_value > 0 ? p_value : -p_value; }

	inline BITMAPINFOHEADER* GetBmiHeader() const { return m_bmiHeader; }
	inline MxLong GetBmiWidth() const { return m_bmiHeader->biWidth; }
	inline MxLong GetBmiStride() const { return ((m_bmiHeader->biWidth + 3) & -4); }
	inline MxLong GetBmiHeight() const { return m_bmiHeader->biHeight; }
	inline MxLong GetBmiHeightAbs() const { return AbsFlipped(m_bmiHeader->biHeight); }
	inline MxU8* GetBitmapData() const { return m_data; }
	inline MxBITMAPINFO* GetBitmapInfo() const { return m_info; }
	inline MxLong GetDataSize() const
	{
		MxLong absHeight = GetBmiHeightAbs();
		MxLong alignedWidth = AlignToFourByte(m_bmiHeader->biWidth);
		return alignedWidth * absHeight;
	}
	inline MxLong GetAdjustedStride()
	{
		if (m_bmiHeader->biCompression == BI_RGB_TOPDOWN || m_bmiHeader->biHeight < 0)
			return GetBmiStride();
		else
			return -GetBmiStride();
	}

	inline MxLong GetLine(MxS32 p_top)
	{
		MxS32 height;
		if (m_bmiHeader->biCompression == BI_RGB_TOPDOWN || m_bmiHeader->biHeight < 0)
			height = p_top;
		else
			height = GetBmiHeightAbs() - p_top - 1;
		return GetBmiStride() * height;
	}

	inline MxU8* GetStart(MxS32 p_left, MxS32 p_top)
	{
		if (m_bmiHeader->biCompression == BI_RGB)
			return GetLine(p_top) + m_data + p_left;
		else if (m_bmiHeader->biCompression == BI_RGB_TOPDOWN)
			return m_data;
		else
			return GetLine(0) + m_data;
	}

	// SYNTHETIC: LEGO1 0x100bc9f0
	// MxBitmap::`scalar deleting destructor'

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
