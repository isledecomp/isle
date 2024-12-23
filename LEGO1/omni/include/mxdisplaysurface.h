#ifndef MXDISPLAYSURFACE_H
#define MXDISPLAYSURFACE_H

#include "decomp.h"
#include "mxcore.h"
#include "mxvideoparam.h"

#include <ddraw.h>

class MxBitmap;
class MxPalette;

// VTABLE: LEGO1 0x100dc768
// SIZE 0xac
class MxDisplaySurface : public MxCore {
public:
	MxDisplaySurface();
	~MxDisplaySurface() override;

	virtual MxResult Init(
		MxVideoParam& p_videoParam,
		LPDIRECTDRAWSURFACE p_ddSurface1,
		LPDIRECTDRAWSURFACE p_ddSurface2,
		LPDIRECTDRAWCLIPPER p_ddClipper
	);                                                   // vtable+0x14
	virtual MxResult Create(MxVideoParam& p_videoParam); // vtable+0x18
	virtual void Destroy();                              // vtable+0x1c
	virtual void SetPalette(MxPalette* p_palette);       // vtable+0x20
	virtual void VTable0x24(
		LPDDSURFACEDESC p_desc,
		MxBitmap* p_bitmap,
		MxS32 p_left,
		MxS32 p_top,
		MxS32 p_right,
		MxS32 p_bottom,
		MxS32 p_width,
		MxS32 p_height
	); // vtable+0x24
	virtual void VTable0x28(
		MxBitmap* p_bitmap,
		MxS32 p_left,
		MxS32 p_top,
		MxS32 p_right,
		MxS32 p_bottom,
		MxS32 p_width,
		MxS32 p_height
	); // vtable+0x28
	virtual void VTable0x2c(
		LPDDSURFACEDESC p_desc,
		MxBitmap* p_bitmap,
		MxS32 p_left,
		MxS32 p_top,
		MxS32 p_right,
		MxS32 p_bottom,
		MxS32 p_width,
		MxS32 p_height,
		MxBool p_RLE
	); // vtable+0x2c
	virtual void VTable0x30(
		MxBitmap* p_bitmap,
		MxS32 p_left,
		MxS32 p_top,
		MxS32 p_right,
		MxS32 p_bottom,
		MxS32 p_width,
		MxS32 p_height,
		MxBool p_RLE
	); // vtable+0x30
	virtual void VTable0x34(
		MxU8* p_pixels,
		MxS32 p_bpp,
		MxS32 p_width,
		MxS32 p_height,
		MxS32 p_x,
		MxS32 p_y
	); // vtable+0x34
	virtual void Display(
		MxS32 p_left,
		MxS32 p_top,
		MxS32 p_left2,
		MxS32 p_top2,
		MxS32 p_width,
		MxS32 p_height
	);                                 // vtable+0x38
	virtual void GetDC(HDC* p_hdc);    // vtable+0x3c
	virtual void ReleaseDC(HDC p_hdc); // vtable+0x40
	virtual LPDIRECTDRAWSURFACE VTable0x44(
		MxBitmap* p_bitmap,
		undefined4* p_ret,
		undefined4 p_doNotWriteToSurface,
		undefined4 p_transparent
	); // vtable+0x44

	void ClearScreen();
	static LPDIRECTDRAWSURFACE CreateCursorSurface();
	static LPDIRECTDRAWSURFACE CopySurface(LPDIRECTDRAWSURFACE p_src);

	LPDIRECTDRAWSURFACE GetDirectDrawSurface1() { return m_ddSurface1; }
	LPDIRECTDRAWSURFACE GetDirectDrawSurface2() { return m_ddSurface2; }
	MxVideoParam& GetVideoParam() { return m_videoParam; }

	void DrawTransparentRLE(
		MxU8*& p_bitmapData,
		MxU8*& p_surfaceData,
		MxU32 p_bitmapSize,
		MxS32 p_width,
		MxS32 p_height,
		MxLong p_pitch,
		MxU8 p_bpp
	);

	LPDIRECTDRAWSURFACE FUN_100bc8b0(MxS32 width, MxS32 height);

private:
	MxU8 CountTotalBitsSetTo1(MxU32 p_param);
	MxU8 CountContiguousBitsSetTo1(MxU32 p_param);

	void Init();

	MxVideoParam m_videoParam;        // 0x08
	LPDIRECTDRAWSURFACE m_ddSurface1; // 0x2c
	LPDIRECTDRAWSURFACE m_ddSurface2; // 0x30
	LPDIRECTDRAWCLIPPER m_ddClipper;  // 0x34
	MxBool m_initialized;             // 0x38
	DDSURFACEDESC m_surfaceDesc;      // 0x3c
	MxU16* m_16bitPal;                // 0xa8
};

// SYNTHETIC: LEGO1 0x100ba580
// MxDisplaySurface::`scalar deleting destructor'

#endif // MXDISPLAYSURFACE_H
