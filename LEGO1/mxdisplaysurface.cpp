#include "mxdisplaysurface.h"

#include "legoomni.h"
#include "mxvideomanager.h"

#include <windows.h>

DECOMP_SIZE_ASSERT(MxDisplaySurface, 0xac);

MxU32 g_unk0x1010215c = 0;

// FUNCTION: LEGO1 0x100ba500
MxDisplaySurface::MxDisplaySurface()
{
	this->Init();
}

// FUNCTION: LEGO1 0x100ba5a0
MxDisplaySurface::~MxDisplaySurface()
{
	this->Destroy();
}

// FUNCTION: LEGO1 0x100ba610
void MxDisplaySurface::Init()
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

		if (hr != DD_OK) {
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
			m_ddSurface1->Flip(NULL, DDFLIP_WAIT);
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
void MxDisplaySurface::Destroy()
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

	this->Init();
}

// FUNCTION: LEGO1 0x100baae0
void MxDisplaySurface::SetPalette(MxPalette* p_palette)
{
	if (m_surfaceDesc.ddpfPixelFormat.dwFlags & DDPF_PALETTEINDEXED8) {
		m_ddSurface1->SetPalette(p_palette->CreateNativePalette());
		m_ddSurface2->SetPalette(p_palette->CreateNativePalette());

		if ((m_videoParam.Flags().GetFullScreen() & 1) == 0) {
			struct {
				WORD m_palVersion;
				WORD m_palNumEntries;
				PALETTEENTRY m_palPalEntry[256];
			} lpal;

			lpal.m_palVersion = 0x300;
			lpal.m_palNumEntries = 256;

			memset(lpal.m_palPalEntry, 0, sizeof(lpal.m_palPalEntry));
			p_palette->GetEntries(lpal.m_palPalEntry);

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

// FUNCTION: LEGO1 0x100bacc0
void MxDisplaySurface::VTable0x28(
	MxBitmap* p_bitmap,
	MxS32 p_left,
	MxS32 p_top,
	MxS32 p_right,
	MxS32 p_bottom,
	MxS32 p_width,
	MxS32 p_height
)
{
	if (FUN_100b6e10(
			p_bitmap->GetBmiWidth(),
			p_bitmap->GetBmiHeightAbs(),
			m_videoParam.GetRect().GetWidth(),
			m_videoParam.GetRect().GetHeight(),
			&p_left,
			&p_top,
			&p_right,
			&p_bottom,
			&p_width,
			&p_height
		)) {
		DDSURFACEDESC ddsd;
		memset(&ddsd, 0, sizeof(ddsd));
		ddsd.dwSize = sizeof(ddsd);

		HRESULT hr = m_ddSurface2->Lock(NULL, &ddsd, DDLOCK_WAIT, NULL);
		if (hr == DDERR_SURFACELOST) {
			m_ddSurface2->Restore();
			hr = m_ddSurface2->Lock(NULL, &ddsd, DDLOCK_WAIT, NULL);
		}

		if (hr == DD_OK) {
			BITMAPINFOHEADER* biHeader = p_bitmap->GetBmiHeader();
			MxU8* data;

			switch (biHeader->biCompression) {
			case BI_RGB: {
				MxS32 rowsBeforeTop;
				if (p_bitmap->GetBmiHeight() < 0)
					rowsBeforeTop = p_top;
				else
					rowsBeforeTop = p_bitmap->GetBmiHeightAbs() - p_top - 1;
				data = p_bitmap->GetBitmapData() + p_left + (p_bitmap->GetBmiStride() * rowsBeforeTop);
				break;
			}
			case BI_RGB_TOPDOWN:
				data = p_bitmap->GetBitmapData();
				break;
			default: {
				MxS32 rowsBeforeTop;
				if (p_bitmap->GetBmiHeight() < 0)
					rowsBeforeTop = 0;
				else
					rowsBeforeTop = p_bitmap->GetBmiHeightAbs() - 1;
				data = p_bitmap->GetBitmapData() + (p_bitmap->GetBmiStride() * rowsBeforeTop);
			}
			}

			if (m_videoParam.Flags().GetF1bit3()) {
				p_bottom *= 2;
				p_right *= 2;

				switch (m_surfaceDesc.ddpfPixelFormat.dwRGBBitCount) {
				case 8: {
					MxU8* surface = (MxU8*) ddsd.lpSurface + p_right + (p_bottom * ddsd.lPitch);
					MxLong stride;

					if (biHeader->biCompression == BI_RGB_TOPDOWN || p_bitmap->GetBmiHeight() < 0)
						stride = p_bitmap->GetBmiStride();
					else
						stride = -p_bitmap->GetBmiStride();

					MxLong v22 = stride - p_width;
					MxLong v55 = ddsd.lPitch - (2 * p_width);

					while (p_height--) {
						MxU8* surfaceBefore = surface;

						for (MxS32 i = 0; p_width > i; *(surface - 1) = *(data - 1)) {
							MxU8 element = *data++;
							surface += 2;
							++i;
							*(surface - 2) = element;
						}

						data += v22;

						memcpy(&surface[v55], surfaceBefore, 2 * p_width);
						surface = &surface[v55] + ddsd.lPitch;
					}
					break;
				}
				case 16: {
					MxU8* surface = (MxU8*) ddsd.lpSurface + (2 * p_right) + (p_bottom * ddsd.lPitch);
					MxLong stride;

					if (biHeader->biCompression == BI_RGB_TOPDOWN || p_bitmap->GetBmiHeight() < 0)
						stride = p_bitmap->GetBmiStride();
					else
						stride = -p_bitmap->GetBmiStride();

					MxS32 length = p_width * 4;
					MxLong v56 = stride - p_width;
					MxLong v62 = ddsd.lPitch - length;
					MxU16* p16BitPal = m_16bitPal;
					MxS32 height = p_height;

					if (stride != p_width || v62) {
						while (height--) {
							MxU8* surfaceBefore = surface;

							for (MxS32 i = p_width; i > 0; i--) {
								MxU16 element = p16BitPal[*data++];
								surface += 4;
								*((MxU16*) surface - 2) = element;
								*((MxU16*) surface - 1) = element;
							}

							data += v56;
							surface += v62;

							// Odd expression for the length?
							memcpy(surface, surfaceBefore, 4 * ((MxU32) (4 * p_width) / 4));
							surface += ddsd.lPitch;
						}
					}
					else {
						while (height--) {
							MxU8* surfaceBefore = surface;

							for (MxS32 i = p_width; i > 0; i--) {
								MxU16 element = p16BitPal[*data++];
								surface += 4;
								*((MxU16*) surface - 2) = element;
								*((MxU16*) surface - 1) = element;
							}

							memcpy(surface, surfaceBefore, length);
							surface += ddsd.lPitch;
						}
					}
				}
				}
			}
			else {
				switch (m_surfaceDesc.ddpfPixelFormat.dwRGBBitCount) {
				case 8: {
					MxU8* surface = (MxU8*) ddsd.lpSurface + p_right + (p_bottom * ddsd.lPitch);
					MxLong stride;

					if (biHeader->biCompression == BI_RGB_TOPDOWN || p_bitmap->GetBmiHeight() < 0)
						stride = p_bitmap->GetBmiStride();
					else
						stride = -p_bitmap->GetBmiStride();

					MxLong v57 = ddsd.lPitch;
					while (p_height--) {
						memcpy(surface, data, p_width);
						data += stride;
						surface += v57;
					}
					break;
				}
				case 16: {
					MxU8* surface = (MxU8*) ddsd.lpSurface + (2 * p_right) + (p_bottom * ddsd.lPitch);
					MxLong stride;

					if (biHeader->biCompression == BI_RGB_TOPDOWN || p_bitmap->GetBmiHeight() < 0)
						stride = p_bitmap->GetBmiStride();
					else
						stride = -p_bitmap->GetBmiStride();

					MxLong v50 = stride - p_width;
					MxLong length = ddsd.lPitch - (2 * p_width);

					for (MxS32 i = 0; p_height > i; i++) {
						for (MxS32 j = 0; p_width > j; j++) {
							*(MxU16*) (surface) = m_16bitPal[*data++];
							surface += 2;
						}

						data += v50;
						surface += length;
					}
				}
				}
			}

			m_ddSurface2->Unlock(ddsd.lpSurface);
		}
	}
}

// STUB: LEGO1 0x100bb1d0
MxBool MxDisplaySurface::VTable0x30(
	MxBitmap* p_bitmap,
	MxS32 p_left,
	MxS32 p_top,
	MxS32 p_right,
	MxS32 p_bottom,
	MxS32 p_width,
	MxS32 p_height,
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
void MxDisplaySurface::Display(MxS32 p_left, MxS32 p_top, MxS32 p_left2, MxS32 p_top2, MxS32 p_width, MxS32 p_height)
{
	if (m_videoParam.Flags().GetF2bit1()) {
		if (m_videoParam.Flags().GetFlipSurfaces()) {
			if (g_unk0x1010215c < 2) {
				g_unk0x1010215c++;

				DDSURFACEDESC ddsd;
				memset(&ddsd, 0, sizeof(ddsd));
				ddsd.dwSize = sizeof(ddsd);
				if (m_ddSurface2->Lock(NULL, &ddsd, DDLOCK_WAIT, NULL) == DD_OK) {
					MxU8* surface = (MxU8*) ddsd.lpSurface;
					MxS32 height = m_videoParam.GetRect().GetHeight();

					for (MxU32 i = 0; i < ddsd.dwHeight; i++) {
						memset(surface, 0, ddsd.dwWidth * ddsd.ddpfPixelFormat.dwRGBBitCount / 8);
						surface += ddsd.lPitch;
					}

					m_ddSurface2->Unlock(ddsd.lpSurface);
				}
				else {
					OutputDebugString("MxDisplaySurface::Display error\n");
				}
			}
			m_ddSurface1->Flip(NULL, DDFLIP_WAIT);
		}
		else {
			POINT point = {0, 0};
			ClientToScreen(MxOmni::GetInstance()->GetWindowHandle(), &point);

			// TODO: Match
			RECT rect1, rect2;
			rect1.left = p_left2 + m_videoParam.GetRect().GetLeft() + point.x;
			rect2.left = p_left;
			rect1.top = p_top2 + m_videoParam.GetRect().GetTop() + point.y;
			rect2.right = p_left + p_width;
			rect2.top = p_top;
			rect2.bottom = p_top + p_height;
			rect1.right = rect1.left + p_width;
			rect1.bottom = rect1.top + p_height;

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
