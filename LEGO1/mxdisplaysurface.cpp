#include "mxdisplaysurface.h"

#include "mxomni.h"
#include "mxvideomanager.h"

DECOMP_SIZE_ASSERT(MxDisplaySurface, 0xac);

// OFFSET: LEGO1 0x100ba500
MxDisplaySurface::MxDisplaySurface()
{
	this->Reset();
}

// OFFSET: LEGO1 0x100ba5a0
MxDisplaySurface::~MxDisplaySurface()
{
	this->Clear();
}

// OFFSET: LEGO1 0x100ba610
void MxDisplaySurface::Reset()
{
	this->m_ddSurface1 = NULL;
	this->m_ddSurface2 = NULL;
	this->m_ddClipper = NULL;
	this->m_16bitPal = NULL;
	this->m_initialized = FALSE;
	memset(&this->m_surfaceDesc, 0, sizeof(this->m_surfaceDesc));
}

// OFFSET: LEGO1 0x100ba640 STUB
void MxDisplaySurface::FUN_100ba640()
{
	// TODO
}

// OFFSET: LEGO1 0x100ba790
MxResult MxDisplaySurface::Init(
	MxVideoParam& p_videoParam,
	LPDIRECTDRAWSURFACE p_ddSurface1,
	LPDIRECTDRAWSURFACE p_ddSurface2,
	LPDIRECTDRAWCLIPPER p_ddClipper
)
{
	MxResult result = SUCCESS;

	this->m_videoParam = p_videoParam;
	this->m_ddSurface1 = p_ddSurface1;
	this->m_ddSurface2 = p_ddSurface2;
	this->m_ddClipper = p_ddClipper;
	this->m_initialized = FALSE;

	memset(&this->m_surfaceDesc, 0, sizeof(this->m_surfaceDesc));
	this->m_surfaceDesc.dwSize = sizeof(this->m_surfaceDesc);

	if (this->m_ddSurface2->GetSurfaceDesc(&this->m_surfaceDesc))
		result = FAILURE;

	return result;
}

// OFFSET: LEGO1 0x100ba7f0
MxResult MxDisplaySurface::Create(MxVideoParam& p_videoParam)
{
	DDSURFACEDESC ddsd;
	MxResult result = FAILURE;
	LPDIRECTDRAW lpDirectDraw = MVideoManager()->GetDirectDraw();
	HWND hWnd = MxOmni::GetInstance()->GetWindowHandle();

	this->m_initialized = TRUE;
	this->m_videoParam = p_videoParam;

	if (!this->m_videoParam.flags().GetFullScreen())
		this->m_videoParam.flags().SetFlipSurfaces(FALSE);

	if (!this->m_videoParam.flags().GetFlipSurfaces()) {
		this->m_videoParam.SetBackBuffers(1);
	}
	else {
		MxU32 backBuffers = this->m_videoParam.GetBackBuffers();

		if (backBuffers < 1)
			this->m_videoParam.SetBackBuffers(1);
		else if (backBuffers > 2)
			this->m_videoParam.SetBackBuffers(2);

		this->m_videoParam.flags().SetBackBuffers(TRUE);
	}

	if (this->m_videoParam.flags().GetFullScreen()) {
		MxS32 width = this->m_videoParam.GetRect().GetWidth();
		MxS32 height = this->m_videoParam.GetRect().GetHeight();

		if (lpDirectDraw->SetCooperativeLevel(hWnd, DDSCL_EXCLUSIVE | DDSCL_FULLSCREEN))
			goto done;

		memset(&ddsd, 0, sizeof(ddsd));
		ddsd.dwSize = sizeof(ddsd);

		if (lpDirectDraw->GetDisplayMode(&ddsd))
			goto done;

		MxS32 bitdepth = !this->m_videoParam.flags().Get16Bit() ? 8 : 16;

		if (ddsd.dwWidth != width || ddsd.dwHeight != height || ddsd.ddpfPixelFormat.dwRGBBitCount != bitdepth) {
			if (lpDirectDraw->SetDisplayMode(width, height, bitdepth))
				goto done;
		}
	}

	if (this->m_videoParam.flags().GetFlipSurfaces()) {
		memset(&ddsd, 0, sizeof(ddsd));
		ddsd.dwSize = sizeof(ddsd);
		ddsd.dwBackBufferCount = this->m_videoParam.GetBackBuffers();
		ddsd.dwFlags = DDSD_CAPS | DDSD_BACKBUFFERCOUNT;
		ddsd.ddsCaps.dwCaps = DDSCAPS_3DDEVICE | DDSCAPS_PRIMARYSURFACE | DDSCAPS_FLIP | DDSCAPS_COMPLEX;

		if (lpDirectDraw->CreateSurface(&ddsd, &this->m_ddSurface1, NULL))
			goto done;

		ddsd.ddsCaps.dwCaps = DDSCAPS_BACKBUFFER;

		if (this->m_ddSurface1->GetAttachedSurface(&ddsd.ddsCaps, &this->m_ddSurface2))
			goto done;
	}
	else {
		memset(&ddsd, 0, sizeof(ddsd));
		ddsd.dwSize = sizeof(ddsd);
		ddsd.dwFlags = DDSD_CAPS;
		ddsd.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE;

		if (lpDirectDraw->CreateSurface(&ddsd, &this->m_ddSurface1, NULL))
			goto done;

		memset(&ddsd, 0, sizeof(ddsd));
		ddsd.dwSize = sizeof(ddsd);
		ddsd.dwFlags = DDSD_HEIGHT | DDSD_WIDTH | DDSD_CAPS;
		ddsd.dwWidth = this->m_videoParam.GetRect().GetWidth();
		ddsd.dwHeight = this->m_videoParam.GetRect().GetHeight();
		ddsd.ddsCaps.dwCaps = DDSCAPS_VIDEOMEMORY | DDSCAPS_3DDEVICE | DDSCAPS_OFFSCREENPLAIN;

		if (!this->m_videoParam.flags().GetBackBuffers())
			ddsd.ddsCaps.dwCaps = DDSCAPS_3DDEVICE | DDSCAPS_SYSTEMMEMORY | DDSCAPS_OFFSCREENPLAIN;

		if (lpDirectDraw->CreateSurface(&ddsd, &this->m_ddSurface2, NULL))
			goto done;
	}

	memset(&this->m_surfaceDesc, 0, sizeof(this->m_surfaceDesc));
	this->m_surfaceDesc.dwSize = sizeof(this->m_surfaceDesc);

	if (!this->m_ddSurface2->GetSurfaceDesc(&this->m_surfaceDesc)) {
		if (!lpDirectDraw->CreateClipper(0, &this->m_ddClipper, NULL) && !this->m_ddClipper->SetHWnd(0, hWnd) &&
			!this->m_ddSurface1->SetClipper(this->m_ddClipper))
			result = SUCCESS;
	}

done:
	return result;
}

// OFFSET: LEGO1 0x100baa90
void MxDisplaySurface::Clear()
{
	if (this->m_initialized) {
		if (this->m_ddSurface2)
			this->m_ddSurface2->Release();

		if (this->m_ddSurface1)
			this->m_ddSurface1->Release();

		if (this->m_ddClipper)
			this->m_ddClipper->Release();
	}

	if (this->m_16bitPal)
		delete this->m_16bitPal;

	this->Reset();
}

// OFFSET: LEGO1 0x100baae0 STUB
void MxDisplaySurface::SetPalette(MxPalette* p_palette)
{
}

// OFFSET: LEGO1 0x100bacc0 STUB
MxBool MxDisplaySurface::vtable28(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4)
{
	return 0;
}

// OFFSET: LEGO1 0x100bb1d0 STUB
MxBool MxDisplaySurface::vtable30(
	undefined4,
	undefined4,
	undefined4,
	undefined4,
	undefined4,
	undefined4,
	undefined4,
	MxBool
)
{
	return 0;
}

// OFFSET: LEGO1 0x100bb850 STUB
undefined4 MxDisplaySurface::vtable34(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4)
{
	return 0;
}

// OFFSET: LEGO1 0x100bba50 STUB
void MxDisplaySurface::Display(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4)
{
}

// OFFSET: LEGO1 0x100bbc10
void MxDisplaySurface::GetDC(HDC* p_hdc)
{
	if (this->m_ddSurface2 && !this->m_ddSurface2->GetDC(p_hdc))
		return;

	*p_hdc = NULL;
}

// OFFSET: LEGO1 0x100bbc40
void MxDisplaySurface::ReleaseDC(HDC p_hdc)
{
	if (this->m_ddSurface2 && p_hdc)
		this->m_ddSurface2->ReleaseDC(p_hdc);
}

// OFFSET: LEGO1 0x100bbc60 STUB
undefined4 MxDisplaySurface::vtable44(undefined4, undefined4*, undefined4, undefined4)
{
	return 0;
}

// OFFSET: LEGO1 0x100bc200 STUB
void MxDisplaySurface::vtable24(
	LPDDSURFACEDESC,
	MxBitmap*,
	undefined4,
	undefined4,
	undefined4,
	undefined4,
	undefined4,
	undefined4
)
{
}

// OFFSET: LEGO1 0x100bc630 STUB
MxBool MxDisplaySurface::
	vtable2c(LPDDSURFACEDESC, MxBitmap*, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, MxBool)
{
	return 0;
}
