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

// FUNCTION: LEGO1 0x100ba750
MxU8 MxDisplaySurface::CountTotalBitsSetTo1(MxU32 p_param)
{
	MxU8 count = 0;

	for (; p_param; p_param >>= 1)
		count += ((MxU8) p_param & 1);

	return count;
}

// FUNCTION: LEGO1 0x100ba770
MxU8 MxDisplaySurface::CountContiguousBitsSetTo1(MxU32 p_param)
{
	MxU8 count = 0;

	for (; (p_param & 1) == 0; p_param >>= 1)
		count++;

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
	if (m_surfaceDesc.ddpfPixelFormat.dwFlags & DDPF_PALETTEINDEXED8) {
		m_ddSurface1->SetPalette(p_palette->CreateNativePalette());
		m_ddSurface2->SetPalette(p_palette->CreateNativePalette());

		if ((m_videoParam.Flags().GetFullScreen() & 1) == 0) {
			struct {
				WORD palVersion;
				WORD palNumEntries;
				PALETTEENTRY palPalEntry[256];
			} lpal;

			lpal.palVersion = 0x300;
			lpal.palNumEntries = 256;

			memset(lpal.palPalEntry, 0, sizeof(lpal.palPalEntry));
			p_palette->GetEntries(lpal.palPalEntry);

			HPALETTE hpal = CreatePalette((LPLOGPALETTE) &lpal);
			HDC hdc = ::GetDC(0);
			SelectPalette(hdc, hpal, FALSE);
			RealizePalette(hdc);
			::ReleaseDC(NULL, hdc);
			DeleteObject(hpal);
		}
	}

	if (m_surfaceDesc.ddpfPixelFormat.dwRGBBitCount == 16) {
		if (!m_16bitPal)
			m_16bitPal = new MxU16[256];

		PALETTEENTRY palette[256];
		p_palette->GetEntries(palette);

		MxU8 contiguousBitsRed = CountContiguousBitsSetTo1(m_surfaceDesc.ddpfPixelFormat.dwRBitMask);
		MxU8 totalBitsRed = CountTotalBitsSetTo1(m_surfaceDesc.ddpfPixelFormat.dwRBitMask);
		MxU8 contiguousBitsGreen = CountContiguousBitsSetTo1(m_surfaceDesc.ddpfPixelFormat.dwGBitMask);
		MxU8 totalBitsGreen = CountTotalBitsSetTo1(m_surfaceDesc.ddpfPixelFormat.dwGBitMask);
		MxU8 contiguousBitsBlue = CountContiguousBitsSetTo1(m_surfaceDesc.ddpfPixelFormat.dwBBitMask);
		MxU8 totalBitsBlue = CountTotalBitsSetTo1(m_surfaceDesc.ddpfPixelFormat.dwBBitMask);

		for (MxS32 i = 0; i < 256; i++) {
			m_16bitPal[i] = (((palette[i].peRed >> (8 - totalBitsRed & 0x1f)) << (contiguousBitsRed & 0x1f))) |
							(((palette[i].peGreen >> (8 - totalBitsGreen & 0x1f)) << (contiguousBitsGreen & 0x1f))) |
							(((palette[i].peBlue >> (8 - totalBitsBlue & 0x1f)) << (contiguousBitsBlue & 0x1f)));
		}
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
