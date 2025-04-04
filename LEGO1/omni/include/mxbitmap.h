#ifndef MXBITMAP_H
#define MXBITMAP_H

#include "mxcore.h"
#include "mxtypes.h"

#include <ddraw.h>
#include <stdlib.h>

class MxPalette;

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
// VTABLE: BETA10 0x101c21f8
class MxBitmap : public MxCore {
public:
	MxBitmap();
	~MxBitmap() override; // vtable+00

	virtual MxResult ImportBitmap(MxBitmap* p_bitmap);                                     // vtable+0x14
	virtual MxResult ImportBitmapInfo(MxBITMAPINFO* p_info);                               // vtable+0x18
	virtual MxResult SetSize(MxS32 p_width, MxS32 p_height, MxPalette* p_palette, MxBool); // vtable+0x1c
	virtual MxResult LoadFile(HANDLE p_handle);                                            // vtable+0x20
	virtual MxLong Read(const char* p_filename);                                           // vtable+0x24

	// FUNCTION: LEGO1 0x1004e0d0
	// FUNCTION: BETA10 0x10060fc0
	virtual MxS32 VTable0x28(MxS32) { return -1; } // vtable+0x28

	virtual void BitBlt(
		MxBitmap* p_src,
		MxS32 p_left,
		MxS32 p_top,
		MxS32 p_right,
		MxS32 p_bottom,
		MxS32 p_width,
		MxS32 p_height
	); // vtable+0x2c
	virtual void BitBltTransparent(
		MxBitmap* p_src,
		MxS32 p_left,
		MxS32 p_top,
		MxS32 p_right,
		MxS32 p_bottom,
		MxS32 p_width,
		MxS32 p_height
	);                                                // vtable+0x30
	virtual MxPalette* CreatePalette();               // vtable+0x34
	virtual void ImportPalette(MxPalette* p_palette); // vtable+0x38
	virtual MxResult SetBitDepth(MxBool);             // vtable+0x3c
	virtual MxResult StretchBits(
		HDC p_hdc,
		MxS32 p_xSrc,
		MxS32 p_ySrc,
		MxS32 p_xDest,
		MxS32 p_yDest,
		MxS32 p_destWidth,
		MxS32 p_destHeight
	); // vtable+0x40

	// Bit mask trick to round up to the nearest multiple of four.
	// Pixel data may be stored with padding.
	// https://learn.microsoft.com/en-us/windows/win32/medfound/image-stride
	// FUNCTION: BETA10 0x1002c510
	MxLong AlignToFourByte(MxLong p_value) const { return (p_value + 3) & -4; }

	// DECOMP: This could be a free function. It is static here because it has no
	// reference to "this". In the beta it is called in two places:
	// 1. GetBmiHeightAbs
	// 2. MxSmk::LoadFrame
	// FUNCTION: BETA10 0x1002c690
	static MxLong HeightAbs(MxLong p_value) { return p_value > 0 ? p_value : -p_value; }

	// FUNCTION: BETA10 0x10142030
	BITMAPINFOHEADER* GetBmiHeader() const { return m_bmiHeader; }

	// FUNCTION: BETA10 0x1002c440
	MxLong GetBmiWidth() const { return m_bmiHeader->biWidth; }
	MxLong GetBmiStride() const { return ((m_bmiHeader->biWidth + 3) & -4); }
	MxLong GetBmiHeight() const { return m_bmiHeader->biHeight; }

	// FUNCTION: BETA10 0x1002c470
	MxLong GetBmiHeightAbs() const { return HeightAbs(m_bmiHeader->biHeight); }

	// FUNCTION: BETA10 0x10083900
	MxU8* GetImage() const { return m_data; }

	// FUNCTION: BETA10 0x100838d0
	MxBITMAPINFO* GetBitmapInfo() const { return m_info; }

	// FUNCTION: BETA10 0x100982b0
	MxLong GetDataSize() const { return AlignToFourByte(m_bmiHeader->biWidth) * GetBmiHeightAbs(); }

	// FUNCTION: BETA10 0x1002c4b0
	MxBool IsTopDown() const
	{
		if (m_bmiHeader->biCompression == BI_RGB_TOPDOWN) {
			return TRUE;
		}
		else {
			return m_bmiHeader->biHeight < 0;
		}
	}

#define GetAdjustedStride(p_bitmap)                                                                                    \
	(p_bitmap->IsTopDown() ? p_bitmap->AlignToFourByte(p_bitmap->GetBmiWidth())                                        \
						   : -p_bitmap->AlignToFourByte(p_bitmap->GetBmiWidth()))

	// FUNCTION: BETA10 0x1002c320
	MxU8* GetStart(MxS32 p_left, MxS32 p_top) const
	{
		if (m_bmiHeader->biCompression == BI_RGB) {
			return m_data + p_left +
				   AlignToFourByte(GetBmiWidth()) * (IsTopDown() ? p_top : (GetBmiHeightAbs() - 1) - p_top);
		}
		else if (m_bmiHeader->biCompression == BI_RGB_TOPDOWN) {
			return m_data;
		}
		else {
			return m_data + AlignToFourByte(GetBmiWidth()) * (IsTopDown() ? 0 : (GetBmiHeightAbs() - 1));
		}
	}

	// SYNTHETIC: LEGO1 0x100bc9f0
	// SYNTHETIC: BETA10 0x1013dcd0
	// MxBitmap::`scalar deleting destructor'

private:
	// FUNCTION: BETA10 0x1013dd10
	MxLong MxBitmapInfoSize() const { return sizeof(MxBITMAPINFO); }

	// FUNCTION: BETA10 0x1013dd30
	MxBool IsBottomUp()
	{
		if (m_bmiHeader->biCompression == BI_RGB_TOPDOWN) {
			return FALSE;
		}
		else {
			return m_bmiHeader->biHeight > 0;
		}
	}

	MxResult ImportColorsToPalette(RGBQUAD*, MxPalette*);

	MxBITMAPINFO* m_info;          // 0x08
	BITMAPINFOHEADER* m_bmiHeader; // 0x0c
	RGBQUAD* m_paletteData;        // 0x10
	MxU8* m_data;                  // 0x14
	MxBool m_isHighColor;          // 0x18
	MxPalette* m_palette;          // 0x1c
};

#endif // MXBITMAP_H
