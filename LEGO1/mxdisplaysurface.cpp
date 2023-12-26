#include "mxdisplaysurface.h"

#include "mxomni.h"
#include "mxvideomanager.h"

DECOMP_SIZE_ASSERT(MxDisplaySurface, 0xac);

MxU32 g_unk0x1010215c = 0;

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

// STUB: LEGO1 0x100baae0
void MxDisplaySurface::SetPalette(MxPalette* p_palette)
{
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

// FUNCTION: LEGO1 0x100bba50
void MxDisplaySurface::Display(MxS16 left, MxS16 top, MxS16 left2, MxS16 top2, MxS16 width, MxS16 height)
{
	if (m_videoParam.Flags().GetF2bit1()) {
		if (m_videoParam.Flags().GetFlipSurfaces() != 0) {
			if (g_unk0x1010215c < 2) {
				g_unk0x1010215c++;

				DDSURFACEDESC ddsd;
				memset(&ddsd, 0, sizeof(ddsd));
				ddsd.dwSize = sizeof(ddsd);
				if (m_ddSurface2->Lock(NULL, &ddsd, 1, NULL) == S_OK) {
					MxU8* surface = (MxU8*) ddsd.lpSurface;
					MxS32 height = m_videoParam.GetRect().GetHeight();

					for (MxU32 i = 0; i < ddsd.dwHeight; i++)
					{
						memset(surface, 0, ddsd.dwWidth * ddsd.ddpfPixelFormat.dwRGBBitCount / 8);
						surface += ddsd.lPitch;
					}

					m_ddSurface2->Unlock(ddsd.lpSurface);
				}
				else {
					OutputDebugString("MxDisplaySurface::Display error\n");
				}
			}
			m_ddSurface1->Flip(NULL, 1);
		}
		else {
			POINT point = {0, 0};
			ClientToScreen(MxOmni::GetInstance()->GetWindowHandle(), &point);

			RECT rect1;
			RECT rect2;
			rect1.left = left2 + m_videoParam.GetRect().GetLeft() + point.x;
			rect2.left = left;
			rect1.top = top2 + m_videoParam.GetRect().GetTop() + point.y;
			rect2.right = left + width;
			rect2.top = top;
			rect2.bottom = top + height;
			rect1.right = rect1.left + width;
			rect1.bottom = rect1.top + height;

			DDBLTFX data;
			memset(&data, 0, sizeof(data));
			data.dwSize = sizeof(data);
			data.dwDDFX = 8;

			if (m_ddSurface1->Blt(&rect1, m_ddSurface2, &rect2, 0, &data) == DDERR_SURFACELOST) {
				m_ddSurface1->Restore();
				m_ddSurface1->Blt(&rect1, m_ddSurface2, &rect2, 0, &data);
			}
		}
	}
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
