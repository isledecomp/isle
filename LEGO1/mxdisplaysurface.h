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

	void Reset();

	void FUN_100ba640();

	virtual MxResult Init(
		MxVideoParam& p_videoParam,
		LPDIRECTDRAWSURFACE p_ddSurface1,
		LPDIRECTDRAWSURFACE p_ddSurface2,
		LPDIRECTDRAWCLIPPER p_ddClipper
	);
	virtual MxResult Create(MxVideoParam& p_videoParam);
	virtual void Clear();
	virtual void SetPalette(MxPalette* p_palette);
	virtual void VTable0x24(
		LPDDSURFACEDESC,
		MxBitmap*,
		undefined4,
		undefined4,
		undefined4,
		undefined4,
		undefined4,
		undefined4
	);
	virtual MxBool VTable0x28(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4);
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
	);
	virtual MxBool VTable0x30(
		undefined4,
		undefined4,
		undefined4,
		undefined4,
		undefined4,
		undefined4,
		undefined4,
		MxBool
	);
	virtual undefined4 VTable0x34(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4);
	virtual void Display(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4);
	virtual void GetDC(HDC* p_hdc);
	virtual void ReleaseDC(HDC p_hdc);
	virtual LPDIRECTDRAWSURFACE VTable0x44(MxBitmap*, undefined4*, undefined4, undefined4);

	inline LPDIRECTDRAWSURFACE GetDirectDrawSurface1() { return this->m_ddSurface1; }
	inline LPDIRECTDRAWSURFACE GetDirectDrawSurface2() { return this->m_ddSurface2; }
	inline MxVideoParam& GetVideoParam() { return this->m_videoParam; }

private:
	MxU8 CountTotalBitsSetTo1(MxU32 p_param);
	MxU8 CountContiguousBitsSetTo1(MxU32 p_param);

	MxVideoParam m_videoParam;
	LPDIRECTDRAWSURFACE m_ddSurface1;
	LPDIRECTDRAWSURFACE m_ddSurface2;
	LPDIRECTDRAWCLIPPER m_ddClipper;
	MxBool m_initialized;
	DDSURFACEDESC m_surfaceDesc;
	MxU16* m_16bitPal;
};

#endif // MXDISPLAYSURFACE_H
