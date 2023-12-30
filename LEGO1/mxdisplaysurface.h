#ifndef MXDISPLAYSURFACE_H
#define MXDISPLAYSURFACE_H

#include "decomp.h"
#include "mxbitmap.h"
#include "mxcore.h"
#include "mxpalette.h"
#include "mxvideoparam.h"

#include <ddraw.h>

// VTABLE: LEGO1 0x100dc768
// SIZE 0xac
class MxDisplaySurface : public MxCore {
public:
	MxDisplaySurface();
	virtual ~MxDisplaySurface() override;

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
		LPDDSURFACEDESC,
		MxBitmap*,
		undefined4,
		undefined4,
		undefined4,
		undefined4,
		undefined4,
		undefined4
	); // vtable+0x24
	virtual MxBool VTable0x28(
		MxBitmap* p_bitmap,
		MxS32 p_left,
		MxS32 p_top,
		MxS32 p_right,
		MxS32 p_bottom,
		MxS32 p_width,
		MxS32 p_height
	); // vtable+0x28
	virtual MxBool VTable0x2c(
		LPDDSURFACEDESC,
		MxBitmap*,
		undefined4,
		undefined4,
		undefined4,
		undefined4,
		undefined4,
		undefined4,
		MxBool
	); // vtable+0x2c
	virtual MxBool VTable0x30(
		MxBitmap* p_bitmap,
		MxS32 p_left,
		MxS32 p_top,
		MxS32 p_right,
		MxS32 p_bottom,
		MxS32 p_width,
		MxS32 p_height,
		MxBool
	); // vtable+0x30
	virtual undefined4 VTable0x34(
		undefined4,
		undefined4,
		undefined4,
		undefined4,
		undefined4,
		undefined4
	); // vtable+0x34
	virtual void Display(
		MxS32 p_left,
		MxS32 p_top,
		MxS32 p_left2,
		MxS32 p_top2,
		MxS32 p_width,
		MxS32 p_height
	);                                                                                      // vtable+0x38
	virtual void GetDC(HDC* p_hdc);                                                         // vtable+0x3c
	virtual void ReleaseDC(HDC p_hdc);                                                      // vtable+0x40
	virtual LPDIRECTDRAWSURFACE VTable0x44(MxBitmap*, undefined4*, undefined4, undefined4); // vtable+0x44

	void FUN_100ba640();

	inline LPDIRECTDRAWSURFACE GetDirectDrawSurface1() { return this->m_ddSurface1; }
	inline LPDIRECTDRAWSURFACE GetDirectDrawSurface2() { return this->m_ddSurface2; }
	inline MxVideoParam& GetVideoParam() { return this->m_videoParam; }

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
