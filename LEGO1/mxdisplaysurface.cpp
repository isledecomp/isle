#include "mxdisplaysurface.h"

#include "mxomni.h"
#include "mxvideomanager.h"
#include <windows.h>

DECOMP_SIZE_ASSERT(MxDisplaySurface, 0xac);

// FUNCTION: LEGO1 0x100ba500
MxDisplaySurface::MxDisplaySurface()
{
	this->Reset();
}

// FUNCTION: LEGO1 0x100ba5a0
MxDisplaySurface::~MxDisplaySurface()
{
	this->Clear();
}

// FUNCTION: LEGO1 0x100ba610
void MxDisplaySurface::Reset()
{
	this->m_ddSurface1 = NULL;
	this->m_ddSurface2 = NULL;
	this->m_ddClipper = NULL;
	this->m_16bitPal = NULL;
	this->m_initialized = FALSE;
	memset(&this->m_surfaceDesc, 0, sizeof(this->m_surfaceDesc));
}

// FUNCTION: LEGO1 0x100ba640
void MxDisplaySurface::FUN_100ba640()
{
	MxS32 backBuffers;
	DDSURFACEDESC desc;
	HRESULT hr;

	if (!m_videoParam.Flags().GetFlipSurfaces()) {
		backBuffers = 1;
	}
	else {
		backBuffers = m_videoParam.GetBackBuffers() + 1;
	}

	for (MxS32 i = 0; i < backBuffers; i++) {
		memset(&desc, 0, sizeof(DDSURFACEDESC));

		desc.dwSize = sizeof(DDSURFACEDESC);
		hr = m_ddSurface2->Lock(NULL, &desc, DDLOCK_WAIT, NULL);
		if (hr == DDERR_SURFACELOST) {
			m_ddSurface2->Restore();
			hr = m_ddSurface2->Lock(NULL, &desc, DDLOCK_WAIT, NULL);
		}

		if (hr != S_OK) {
			return;
		}

		MxU8* surface = (MxU8*) desc.lpSurface;
		MxS32 height = m_videoParam.GetRect().GetHeight();

		while (height--) {
			memset(surface, 0, m_videoParam.GetRect().GetWidth() * desc.ddpfPixelFormat.dwRGBBitCount / 8);
			surface += desc.lPitch;
		}

		m_ddSurface2->Unlock(desc.lpSurface);
		if (m_videoParam.Flags().GetFlipSurfaces()) {
			m_ddSurface1->Flip(NULL, 1);
		}
	}
}

// OFFSET: LEGO1 0x100ba750
byte CountTotalBitsSetTo1(MxU32 p_param)
{
	MxU32 a;
	byte i = 0;
	if(p_param) {
		do {
			a = i >> 1;
			i += ((byte)p_param & 1);
			p_param = a;
		} while (a != 0);
	}
	return i;
}

// OFFSET: LEGO1 0x100ba770
byte CountContiguousBitsSetTo1(MxU32 p_param)
{
	MxU32 u;
	byte count = 0;
	
	u = p_param & 1;
	while(u == 0) {
		p_param >>= 1;
		count++;
		u = p_param & 1;
	}
	return count;
}

// FUNCTION: LEGO1 0x100ba790
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

// FUNCTION: LEGO1 0x100ba7f0
MxResult MxDisplaySurface::Create(MxVideoParam& p_videoParam)
{
	DDSURFACEDESC ddsd;
	MxResult result = FAILURE;
	LPDIRECTDRAW lpDirectDraw = MVideoManager()->GetDirectDraw();
	HWND hWnd = MxOmni::GetInstance()->GetWindowHandle();

	this->m_initialized = TRUE;
	this->m_videoParam = p_videoParam;

	if (!this->m_videoParam.Flags().GetFullScreen())
		this->m_videoParam.Flags().SetFlipSurfaces(FALSE);

	if (!this->m_videoParam.Flags().GetFlipSurfaces()) {
		this->m_videoParam.SetBackBuffers(1);
	}
	else {
		MxU32 backBuffers = this->m_videoParam.GetBackBuffers();

		if (backBuffers < 1)
			this->m_videoParam.SetBackBuffers(1);
		else if (backBuffers > 2)
			this->m_videoParam.SetBackBuffers(2);

		this->m_videoParam.Flags().SetBackBuffers(TRUE);
	}

	if (this->m_videoParam.Flags().GetFullScreen()) {
		MxS32 width = this->m_videoParam.GetRect().GetWidth();
		MxS32 height = this->m_videoParam.GetRect().GetHeight();

		if (lpDirectDraw->SetCooperativeLevel(hWnd, DDSCL_EXCLUSIVE | DDSCL_FULLSCREEN))
			goto done;

		memset(&ddsd, 0, sizeof(ddsd));
		ddsd.dwSize = sizeof(ddsd);

		if (lpDirectDraw->GetDisplayMode(&ddsd))
			goto done;

		MxS32 bitdepth = !this->m_videoParam.Flags().Get16Bit() ? 8 : 16;

		if (ddsd.dwWidth != width || ddsd.dwHeight != height || ddsd.ddpfPixelFormat.dwRGBBitCount != bitdepth) {
			if (lpDirectDraw->SetDisplayMode(width, height, bitdepth))
				goto done;
		}
	}

	if (this->m_videoParam.Flags().GetFlipSurfaces()) {
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

		if (!this->m_videoParam.Flags().GetBackBuffers())
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

// FUNCTION: LEGO1 0x100baa90
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

// FUNCTION: LEGO1 0x100baae0
void MxDisplaySurface::SetPalette(MxPalette* p_palette)
{
	HDC hdc;
	MxS32 j;
	HPALETTE hpal;
	LOGPALETTE lpal;
	byte bVar2;
  	byte bVar3;
  	byte bVar4;
  	byte bVar5;
  	byte bVar6;
  	byte bVar7;
	if(((this->m_surfaceDesc).ddpfPixelFormat.dwFlags & 0x20) != 0) {
		this->m_ddSurface1->SetPalette(p_palette->CreateNativePalette());
		this->m_ddSurface2->SetPalette(p_palette->CreateNativePalette());
		if(((this->m_videoParam).Flags().GetFullScreen() & 1) == 0) {
			lpal.palVersion = 0x300;
			// lpal.palNumEntries = 256;
			// FIXME: this loop may be incorrect
			memcpy(lpal.palPalEntry, NULL, sizeof(lpal.palNumEntries));

			p_palette->GetEntries(lpal.palPalEntry);
			hpal = CreatePalette(&lpal);
			hdc = ::GetDC(0);
			SelectPalette(hdc, hpal, 0);
			RealizePalette(hdc);
			::ReleaseDC(0, hdc);
			DeleteObject(hpal);
		}
	}
	if((this->m_surfaceDesc).ddpfPixelFormat.dwRGBBitCount == 16) {
		if(this->m_16bitPal == NULL) {
			this->m_16bitPal = new(MxU16); // FIXME: malloc size 512;
		}
		p_palette->GetEntries((PALETTEENTRY*) &lpal);  // ?

		// It looks like the arguments are correct - the offsets match but the registers are swapped
		bVar2 = CountContiguousBitsSetTo1((this->m_surfaceDesc).ddpfPixelFormat.dwRBitMask);
    	bVar3 = CountTotalBitsSetTo1((this->m_surfaceDesc).ddpfPixelFormat.dwRBitMask);
    	bVar4 = CountContiguousBitsSetTo1((this->m_surfaceDesc).ddpfPixelFormat.dwGBitMask);
    	bVar5 = CountTotalBitsSetTo1((this->m_surfaceDesc).ddpfPixelFormat.dwGBitMask);
    	bVar6 = CountContiguousBitsSetTo1((this->m_surfaceDesc).ddpfPixelFormat.dwBBitMask);
    	bVar7 = CountTotalBitsSetTo1((this->m_surfaceDesc).ddpfPixelFormat.dwBBitMask);

		MxS32 i = 0;
		WORD e = lpal.palNumEntries;
		do {
			j = i + 2;

			// this line is probably very incorrect
			*this->m_16bitPal = e >> (8 - bVar3 & 0x1f) << (bVar2 & 0x1f) | e >> (8 - bVar5 & 0x1f) << (bVar4 & 0x1f) | e >> (8 - bVar7 & 0x1f) << (bVar6 & 0x1f);
			i = j;
			e += 2;
		} while (j < 512);
	}
}

// STUB: LEGO1 0x100bacc0
MxBool MxDisplaySurface::VTable0x28(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4)
{
	return 0;
}

// STUB: LEGO1 0x100bb1d0
MxBool MxDisplaySurface::VTable0x30(
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

// STUB: LEGO1 0x100bb850
undefined4 MxDisplaySurface::VTable0x34(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4)
{
	return 0;
}

// STUB: LEGO1 0x100bba50
void MxDisplaySurface::Display(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4)
{
}

// FUNCTION: LEGO1 0x100bbc10
void MxDisplaySurface::GetDC(HDC* p_hdc)
{
	if (this->m_ddSurface2 && !this->m_ddSurface2->GetDC(p_hdc))
		return;

	*p_hdc = NULL;
}

// FUNCTION: LEGO1 0x100bbc40
void MxDisplaySurface::ReleaseDC(HDC p_hdc)
{
	if (this->m_ddSurface2 && p_hdc)
		this->m_ddSurface2->ReleaseDC(p_hdc);
}

// STUB: LEGO1 0x100bbc60
LPDIRECTDRAWSURFACE MxDisplaySurface::VTable0x44(MxBitmap*, undefined4*, undefined4, undefined4)
{
	return NULL;
}

// STUB: LEGO1 0x100bc200
void MxDisplaySurface::VTable0x24(
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

// STUB: LEGO1 0x100bc630
MxBool MxDisplaySurface::VTable0x2c(
	LPDDSURFACEDESC,
	MxBitmap*,
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
