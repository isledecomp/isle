#include "mxdisplaysurface.h"

#include "mxbitmap.h"
#include "mxmisc.h"
#include "mxomni.h"
#include "mxpalette.h"
#include "mxutilities.h"
#include "mxvideomanager.h"

#include <assert.h>
#include <windows.h>

DECOMP_SIZE_ASSERT(MxDisplaySurface, 0xac);

// GLOBAL: LEGO1 0x1010215c
MxU32 g_unk0x1010215c = 0;

// FUNCTION: LEGO1 0x100ba500
MxDisplaySurface::MxDisplaySurface()
{
	Init();
}

// FUNCTION: LEGO1 0x100ba5a0
MxDisplaySurface::~MxDisplaySurface()
{
	Destroy();
}

// FUNCTION: LEGO1 0x100ba610
void MxDisplaySurface::Init()
{
	m_ddSurface1 = NULL;
	m_ddSurface2 = NULL;
	m_ddClipper = NULL;
	m_16bitPal = NULL;
	m_initialized = FALSE;
	memset(&m_surfaceDesc, 0, sizeof(m_surfaceDesc));
}

// FUNCTION: LEGO1 0x100ba640
void MxDisplaySurface::ClearScreen()
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

	for (; p_param; p_param >>= 1) {
		count += ((MxU8) p_param & 1);
	}

	return count;
}

// FUNCTION: LEGO1 0x100ba770
MxU8 MxDisplaySurface::CountContiguousBitsSetTo1(MxU32 p_param)
{
	MxU8 count = 0;

	for (; (p_param & 1) == 0; p_param >>= 1) {
		count++;
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

	m_videoParam = p_videoParam;
	m_ddSurface1 = p_ddSurface1;
	m_ddSurface2 = p_ddSurface2;
	m_ddClipper = p_ddClipper;
	m_initialized = FALSE;

	memset(&m_surfaceDesc, 0, sizeof(m_surfaceDesc));
	m_surfaceDesc.dwSize = sizeof(m_surfaceDesc);

	if (m_ddSurface2->GetSurfaceDesc(&m_surfaceDesc)) {
		result = FAILURE;
	}

	return result;
}

// FUNCTION: LEGO1 0x100ba7f0
MxResult MxDisplaySurface::Create(MxVideoParam& p_videoParam)
{
	DDSURFACEDESC ddsd;
	MxResult result = FAILURE;
	LPDIRECTDRAW lpDirectDraw = MVideoManager()->GetDirectDraw();
	HWND hWnd = MxOmni::GetInstance()->GetWindowHandle();

	m_initialized = TRUE;
	m_videoParam = p_videoParam;

	if (!m_videoParam.Flags().GetFullScreen()) {
		m_videoParam.Flags().SetFlipSurfaces(FALSE);
	}

	if (!m_videoParam.Flags().GetFlipSurfaces()) {
		m_videoParam.SetBackBuffers(1);
	}
	else {
		MxU32 backBuffers = m_videoParam.GetBackBuffers();

		if (backBuffers < 1) {
			m_videoParam.SetBackBuffers(1);
		}
		else if (backBuffers > 2) {
			m_videoParam.SetBackBuffers(2);
		}

		m_videoParam.Flags().SetBackBuffers(TRUE);
	}

	if (m_videoParam.Flags().GetFullScreen()) {
		MxS32 width = m_videoParam.GetRect().GetWidth();
		MxS32 height = m_videoParam.GetRect().GetHeight();

		if (lpDirectDraw->SetCooperativeLevel(hWnd, DDSCL_EXCLUSIVE | DDSCL_FULLSCREEN)) {
			goto done;
		}

		memset(&ddsd, 0, sizeof(ddsd));
		ddsd.dwSize = sizeof(ddsd);

		if (lpDirectDraw->GetDisplayMode(&ddsd)) {
			goto done;
		}

		MxS32 bitdepth = !m_videoParam.Flags().Get16Bit() ? 8 : 16;

		if (ddsd.dwWidth != width || ddsd.dwHeight != height || ddsd.ddpfPixelFormat.dwRGBBitCount != bitdepth) {
			if (lpDirectDraw->SetDisplayMode(width, height, bitdepth)) {
				goto done;
			}
		}
	}

	if (m_videoParam.Flags().GetFlipSurfaces()) {
		memset(&ddsd, 0, sizeof(ddsd));
		ddsd.dwSize = sizeof(ddsd);
		ddsd.dwBackBufferCount = m_videoParam.GetBackBuffers();
		ddsd.dwFlags = DDSD_CAPS | DDSD_BACKBUFFERCOUNT;
		ddsd.ddsCaps.dwCaps = DDSCAPS_3DDEVICE | DDSCAPS_PRIMARYSURFACE | DDSCAPS_FLIP | DDSCAPS_COMPLEX;

		if (lpDirectDraw->CreateSurface(&ddsd, &m_ddSurface1, NULL)) {
			goto done;
		}

		ddsd.ddsCaps.dwCaps = DDSCAPS_BACKBUFFER;

		if (m_ddSurface1->GetAttachedSurface(&ddsd.ddsCaps, &m_ddSurface2)) {
			goto done;
		}
	}
	else {
		memset(&ddsd, 0, sizeof(ddsd));
		ddsd.dwSize = sizeof(ddsd);
		ddsd.dwFlags = DDSD_CAPS;
		ddsd.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE;

		if (lpDirectDraw->CreateSurface(&ddsd, &m_ddSurface1, NULL)) {
			goto done;
		}

		memset(&ddsd, 0, sizeof(ddsd));
		ddsd.dwSize = sizeof(ddsd);
		ddsd.dwFlags = DDSD_HEIGHT | DDSD_WIDTH | DDSD_CAPS;
		ddsd.dwWidth = m_videoParam.GetRect().GetWidth();
		ddsd.dwHeight = m_videoParam.GetRect().GetHeight();
		ddsd.ddsCaps.dwCaps = DDSCAPS_VIDEOMEMORY | DDSCAPS_3DDEVICE | DDSCAPS_OFFSCREENPLAIN;

		if (!m_videoParam.Flags().GetBackBuffers()) {
			ddsd.ddsCaps.dwCaps = DDSCAPS_3DDEVICE | DDSCAPS_SYSTEMMEMORY | DDSCAPS_OFFSCREENPLAIN;
		}

		if (lpDirectDraw->CreateSurface(&ddsd, &m_ddSurface2, NULL)) {
			goto done;
		}
	}

	memset(&m_surfaceDesc, 0, sizeof(m_surfaceDesc));
	m_surfaceDesc.dwSize = sizeof(m_surfaceDesc);

	if (!m_ddSurface2->GetSurfaceDesc(&m_surfaceDesc)) {
		if (!lpDirectDraw->CreateClipper(0, &m_ddClipper, NULL) && !m_ddClipper->SetHWnd(0, hWnd) &&
			!m_ddSurface1->SetClipper(m_ddClipper)) {
			result = SUCCESS;
		}
	}

done:
	return result;
}

// FUNCTION: LEGO1 0x100baa90
void MxDisplaySurface::Destroy()
{
	if (m_initialized) {
		if (m_ddSurface2) {
			m_ddSurface2->Release();
		}

		if (m_ddSurface1) {
			m_ddSurface1->Release();
		}

		if (m_ddClipper) {
			m_ddClipper->Release();
		}
	}

	if (m_16bitPal) {
		delete[] m_16bitPal;
	}

	Init();
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
		if (!m_16bitPal) {
			m_16bitPal = new MxU16[256];
		}

		PALETTEENTRY palette[256];
		p_palette->GetEntries(palette);

		MxU8 contiguousBitsRed = CountContiguousBitsSetTo1(m_surfaceDesc.ddpfPixelFormat.dwRBitMask);
		MxU8 totalBitsRed = CountTotalBitsSetTo1(m_surfaceDesc.ddpfPixelFormat.dwRBitMask);
		MxU8 contiguousBitsGreen = CountContiguousBitsSetTo1(m_surfaceDesc.ddpfPixelFormat.dwGBitMask);
		MxU8 totalBitsGreen = CountTotalBitsSetTo1(m_surfaceDesc.ddpfPixelFormat.dwGBitMask);
		MxU8 contiguousBitsBlue = CountContiguousBitsSetTo1(m_surfaceDesc.ddpfPixelFormat.dwBBitMask);
		MxU8 totalBitsBlue = CountTotalBitsSetTo1(m_surfaceDesc.ddpfPixelFormat.dwBBitMask);

		for (MxS32 i = 0; i < 256; i++) {
			m_16bitPal[i] = (((palette[i].peRed >> ((8 - totalBitsRed) & 0x1f)) << (contiguousBitsRed & 0x1f))) |
							(((palette[i].peGreen >> ((8 - totalBitsGreen) & 0x1f)) << (contiguousBitsGreen & 0x1f))) |
							(((palette[i].peBlue >> ((8 - totalBitsBlue) & 0x1f)) << (contiguousBitsBlue & 0x1f)));
		}
	}
}

// FUNCTION: LEGO1 0x100bacc0
// FUNCTION: BETA10 0x1014012b
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
	if (!GetRectIntersection(
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
		return;
	}
	DDSURFACEDESC ddsd;
	memset(&ddsd, 0, sizeof(ddsd));
	ddsd.dwSize = sizeof(ddsd);

	HRESULT hr = m_ddSurface2->Lock(NULL, &ddsd, DDLOCK_WAIT, NULL);
	if (hr == DDERR_SURFACELOST) {
		m_ddSurface2->Restore();
		hr = m_ddSurface2->Lock(NULL, &ddsd, DDLOCK_WAIT, NULL);
	}

	if (hr != DD_OK) {
		return;
	}

	MxU8* data = p_bitmap->GetStart(p_left, p_top);

	if (m_videoParam.Flags().GetF1bit3()) {
		p_bottom *= 2;
		p_right *= 2;

		switch (m_surfaceDesc.ddpfPixelFormat.dwRGBBitCount) {
		case 8: {
			MxU8* surface = (MxU8*) ddsd.lpSurface + p_right + (p_bottom * ddsd.lPitch);
			MxLong stride = -p_width + GetAdjustedStride(p_bitmap);

			MxLong length = -2 * p_width + ddsd.lPitch;
			while (p_height--) {
				MxU8* surfaceBefore = surface;

				for (MxS32 i = 0; p_width > i; i++) {
					*surface++ = *data;
					*surface++ = *data++;
				}

				data += stride;
				surface += length;

				memcpy(surface, surfaceBefore, 2 * p_width);
				surface += ddsd.lPitch;
			}
			break;
		}
		case 16: {
			MxU8* surface = (MxU8*) ddsd.lpSurface + (2 * p_right) + (p_bottom * ddsd.lPitch);
			MxLong stride = -p_width + GetAdjustedStride(p_bitmap);

			MxS32 length = -4 * p_width + ddsd.lPitch;
			MxS32 height = p_height;
			MxS32 width = p_width;
			MxS32 copyWidth = width * 4;
			MxU16* p16bitPal = m_16bitPal;

			MxS32 i;
			if (stride || length) {
				while (height--) {
					MxU8* surfaceBefore = surface;

					for (i = 0; i < width; i++) {
						MxU16 element = p16bitPal[*data];
						*(MxU16*) surface = element;
						surface += 2;
						*(MxU16*) surface = element;

						data++;
						surface += 2;
					}

					memcpy(surface, surfaceBefore, copyWidth);
					surface += ddsd.lPitch;
				}
			}
			else {
				while (height--) {
					MxU8* surfaceBefore = surface;

					for (i = 0; i < width; i++) {
						MxU16 element = p16bitPal[*data];
						*(MxU16*) surface = element;
						surface += 2;
						*(MxU16*) surface = element;

						data++;
						surface += 2;
					}

					data += stride;
					surface += length;

					memcpy(surface, surfaceBefore, p_width * 4);
					surface += ddsd.lPitch;
				}
			}
			break;
		}
		default:
			break;
		}
	}
	else {
		switch (m_surfaceDesc.ddpfPixelFormat.dwRGBBitCount) {
		case 8: {
			MxU8* surface = (MxU8*) ddsd.lpSurface + p_right + (p_bottom * ddsd.lPitch);
			MxLong stride = GetAdjustedStride(p_bitmap);

			MxLong length = ddsd.lPitch;
			while (p_height--) {
				memcpy(surface, data, p_width);
				data += stride;
				surface += length;
			}
			break;
		}
		case 16: {
			MxU8* surface = (MxU8*) ddsd.lpSurface + (2 * p_right) + (p_bottom * ddsd.lPitch);
			MxLong stride = -p_width + GetAdjustedStride(p_bitmap);

			MxLong length = -2 * p_width + ddsd.lPitch;
			for (MxS32 i = 0; i < p_height; i++) {
				for (MxS32 j = 0; j < p_width; j++) {
					*(MxU16*) surface = m_16bitPal[*data++];
					surface += 2;
				}

				data += stride;
				surface += length;
			}
			break;
		}
		default:
			break;
		}
	}

	m_ddSurface2->Unlock(ddsd.lpSurface);
}

// FUNCTION: LEGO1 0x100bb1d0
// FUNCTION: BETA10 0x1014088e
void MxDisplaySurface::VTable0x30(
	MxBitmap* p_bitmap,
	MxS32 p_left,
	MxS32 p_top,
	MxS32 p_right,
	MxS32 p_bottom,
	MxS32 p_width,
	MxS32 p_height,
	MxBool p_und
)
{
	if (!GetRectIntersection(
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
		return;
	}
	DDSURFACEDESC ddsd;
	memset(&ddsd, 0, sizeof(ddsd));
	ddsd.dwSize = sizeof(ddsd);

	HRESULT hr = m_ddSurface2->Lock(NULL, &ddsd, DDLOCK_WAIT, NULL);
	if (hr == DDERR_SURFACELOST) {
		m_ddSurface2->Restore();
		hr = m_ddSurface2->Lock(NULL, &ddsd, DDLOCK_WAIT, NULL);
	}

	if (hr != DD_OK) {
		return;
	}

	MxU8* data = p_bitmap->GetStart(p_left, p_top);

	switch (m_surfaceDesc.ddpfPixelFormat.dwRGBBitCount) {
	case 8: {
		MxU8* surface = (MxU8*) ddsd.lpSurface + p_right + (p_bottom * ddsd.lPitch);
		if (p_und) {
			MxS32 size = p_bitmap->GetBmiHeader()->biSizeImage;
			DrawTransparentRLE(data, surface, size, p_width, p_height, ddsd.lPitch, 8);
		}
		else {
			MxLong stride = -p_width + GetAdjustedStride(p_bitmap);

			MxLong length = -p_width + ddsd.lPitch;
			for (MxS32 i = 0; i < p_height; i++) {
				for (MxS32 j = 0; j < p_width; j++) {
					if (*data != 0) {
						*surface = *data;
					}

					data++;
					surface++;
				}

				data += stride;
				surface += length;
			}
		}
		break;
	}
	case 16: {
		MxU8* surface = (MxU8*) ddsd.lpSurface + (2 * p_right) + (p_bottom * ddsd.lPitch);
		if (p_und) {
			MxS32 size = p_bitmap->GetBmiHeader()->biSizeImage;
			DrawTransparentRLE(data, surface, size, p_width, p_height, ddsd.lPitch, 16);
		}
		else {
			MxLong stride = -p_width + GetAdjustedStride(p_bitmap);

			MxLong length = -2 * p_width + ddsd.lPitch;
			for (MxS32 i = 0; i < p_height; i++) {
				for (MxS32 j = 0; j < p_width; j++) {
					if (*data != 0) {
						*(MxU16*) surface = m_16bitPal[*data];
					}

					data++;
					surface += 2;
				}

				data += stride;
				surface += length;
			}
		}
		break;
	}
	default:
		break;
	}

	m_ddSurface2->Unlock(ddsd.lpSurface);
}

// FUNCTION: LEGO1 0x100bb500
// FUNCTION: BETA10 0x10140cd6
void MxDisplaySurface::DrawTransparentRLE(
	MxU8*& p_bitmapData,
	MxU8*& p_surfaceData,
	MxU32 p_bitmapSize,
	MxS32 p_width,
	MxS32 p_height,
	MxLong p_pitch,
	MxU8 p_bpp
)
{
	/* Assumes partial RLE for the bitmap: only the skipped pixels are compressed.
	The drawn pixels are uncompressed. The procedure is:
	1. Read 3 bytes from p_bitmapData. Skip this many pixels on the surface.
	2. Read 3 bytes from p_bitmapData. Draw this many pixels on the surface.
	3. Repeat until the end of p_bitmapData is reached. */

	MxU8* end = p_bitmapData + p_bitmapSize;
	MxU8* surfCopy = p_surfaceData; // unused?

	// The total number of pixels drawn or skipped
	MxU32 count = 0;

	// Used in both 8 and 16 bit branches
	MxU32 skipCount;
	MxU32 drawCount;
	MxU32 t;

	if (p_bpp == 16) {
		// DECOMP: why goto?
		goto sixteen_bit;
	}

	while (p_bitmapData < end) {
		skipCount = *p_bitmapData++;
		t = *p_bitmapData++;
		skipCount += t << 8;
		t = *p_bitmapData++;
		skipCount += t << 16;

		MxS32 rowRemainder = p_width - count % p_width;
		count += skipCount;

		if (skipCount >= rowRemainder) {
			p_surfaceData += rowRemainder; // skip the rest of this row
			skipCount -= rowRemainder;
			p_surfaceData += p_pitch - p_width;               // seek to start of next row
			p_surfaceData += p_pitch * (skipCount / p_width); // skip entire rows if any
		}

		// skip any pixels at the start of this row
		p_surfaceData += skipCount % p_width;
		if (p_bitmapData >= end) {
			break;
		}

		drawCount = *p_bitmapData++;
		t = *p_bitmapData++;
		drawCount += t << 8;
		t = *p_bitmapData++;
		drawCount += t << 16;

		rowRemainder = p_width - count % p_width;
		count += drawCount;

		if (drawCount >= rowRemainder) {
			memcpy(p_surfaceData, p_bitmapData, rowRemainder);
			p_surfaceData += rowRemainder;
			p_bitmapData += rowRemainder;

			drawCount -= rowRemainder;

			// seek to start of bitmap on this screen row
			p_surfaceData += p_pitch - p_width;
			MxS32 rows = drawCount / p_width;

			for (MxU32 i = 0; i < rows; i++) {
				memcpy(p_surfaceData, p_bitmapData, p_width);
				p_bitmapData += p_width;
				p_surfaceData += p_pitch;
			}
		}

		MxS32 tail = drawCount % p_width;
		memcpy(p_surfaceData, p_bitmapData, tail);
		p_surfaceData += tail;
		p_bitmapData += tail;
	}
	return;

sixteen_bit:
	while (p_bitmapData < end) {
		skipCount = *p_bitmapData++;
		t = *p_bitmapData++;
		skipCount += t << 8;
		t = *p_bitmapData++;
		skipCount += t << 16;

		MxS32 rowRemainder = p_width - count % p_width;
		count += skipCount;

		if (skipCount >= rowRemainder) {
			p_surfaceData += 2 * rowRemainder;
			skipCount -= rowRemainder;
			p_surfaceData += p_pitch - 2 * p_width;
			p_surfaceData += p_pitch * (skipCount / p_width);
		}

		p_surfaceData += 2 * (skipCount % p_width);
		if (p_bitmapData >= end) {
			break;
		}

		drawCount = *p_bitmapData++;
		t = *p_bitmapData++;
		drawCount += t << 8;
		t = *p_bitmapData++;
		drawCount += t << 16;

		rowRemainder = p_width - count % p_width;
		count += drawCount;

		if (drawCount >= rowRemainder) {
			// memcpy
			for (MxU32 j = 0; j < rowRemainder; j++) {
				*((MxU16*) p_surfaceData) = m_16bitPal[*p_bitmapData++];
				p_surfaceData += 2;
			}

			drawCount -= rowRemainder;

			p_surfaceData += p_pitch - 2 * p_width;
			MxS32 rows = drawCount / p_width;

			for (MxU32 i = 0; i < rows; i++) {
				// memcpy
				for (MxS32 j = 0; j < p_width; j++) {
					*((MxU16*) p_surfaceData) = m_16bitPal[*p_bitmapData++];
					p_surfaceData += 2;
				}

				p_surfaceData += p_pitch - 2 * p_width;
			}
		}

		MxS32 tail = drawCount % p_width;
		// memcpy
		for (MxS32 j = 0; j < tail; j++) {
			*((MxU16*) p_surfaceData) = m_16bitPal[*p_bitmapData++];
			p_surfaceData += 2;
		}
	}
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
			MxPoint32 point(0, 0);
			ClientToScreen(MxOmni::GetInstance()->GetWindowHandle(), (LPPOINT) &point);

			p_left2 += m_videoParam.GetRect().GetLeft() + point.GetX();
			p_top2 += m_videoParam.GetRect().GetTop() + point.GetY();

			MxRect32 a(MxPoint32(p_left, p_top), MxSize32(p_width + 1, p_height + 1));
			MxRect32 b(MxPoint32(p_left2, p_top2), MxSize32(p_width + 1, p_height + 1));

			DDBLTFX data;
			memset(&data, 0, sizeof(data));
			data.dwSize = sizeof(data);
			data.dwDDFX = 8;

			if (m_ddSurface1->Blt((LPRECT) &b, m_ddSurface2, (LPRECT) &a, 0, &data) == DDERR_SURFACELOST) {
				m_ddSurface1->Restore();
				m_ddSurface1->Blt((LPRECT) &b, m_ddSurface2, (LPRECT) &a, 0, &data);
			}
		}
	}
}

// FUNCTION: LEGO1 0x100bbc10
void MxDisplaySurface::GetDC(HDC* p_hdc)
{
	if (m_ddSurface2 && !m_ddSurface2->GetDC(p_hdc)) {
		return;
	}

	*p_hdc = NULL;
}

// FUNCTION: LEGO1 0x100bbc40
void MxDisplaySurface::ReleaseDC(HDC p_hdc)
{
	if (m_ddSurface2 && p_hdc) {
		m_ddSurface2->ReleaseDC(p_hdc);
	}
}

// FUNCTION: LEGO1 0x100bbc60
// FUNCTION: BETA10 0x10141745
LPDIRECTDRAWSURFACE MxDisplaySurface::VTable0x44(
	MxBitmap* p_bitmap,
	undefined4* p_ret,
	undefined4 p_doNotWriteToSurface,
	undefined4 p_transparent
)
{
	LPDIRECTDRAWSURFACE surface = NULL;
	LPDIRECTDRAW draw = MVideoManager()->GetDirectDraw();
	MxVideoParamFlags& flags = MVideoManager()->GetVideoParam().Flags();

	DDSURFACEDESC ddsd;
	memset(&ddsd, 0, sizeof(ddsd));
	ddsd.dwSize = sizeof(ddsd);

	if (draw->GetDisplayMode(&ddsd)) {
		return NULL;
	}

	ddsd.dwFlags = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH | DDSD_PIXELFORMAT;
	ddsd.dwWidth = p_bitmap->GetBmiWidth();
	ddsd.dwHeight = p_bitmap->GetBmiHeightAbs();
	ddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN;
	*p_ret = 0;
	ddsd.ddsCaps.dwCaps |= DDSCAPS_SYSTEMMEMORY;

	if (draw->CreateSurface(&ddsd, &surface, NULL) != DD_OK) {
		if (*p_ret) {
			*p_ret = 0;

			// Try creating bitmap surface in vram if system ram ran out
			ddsd.ddsCaps.dwCaps &= ~DDSCAPS_VIDEOMEMORY;
			ddsd.ddsCaps.dwCaps |= DDSCAPS_SYSTEMMEMORY;

			if (draw->CreateSurface(&ddsd, &surface, NULL) != DD_OK) {
				surface = NULL;
			}
		}
		else {
			surface = NULL;
		}
	}

	if (surface) {
		memset(&ddsd, 0, sizeof(ddsd));
		ddsd.dwSize = sizeof(ddsd);

		if (surface->Lock(NULL, &ddsd, DDLOCK_WAIT, 0) != DD_OK) {
			surface->Release();
			surface = NULL;
		}
		else if (p_doNotWriteToSurface) {
			assert(0);
		}
		else {
			MxU8* bitmapSrcPtr = p_bitmap->GetStart(0, 0);
			MxU16* surfaceData = (MxU16*) ddsd.lpSurface;
			MxLong widthNormal = p_bitmap->GetBmiWidth();
			MxLong heightAbs = p_bitmap->GetBmiHeightAbs();

			MxLong newPitch = ddsd.lPitch;
			MxS32 rowSeek = p_bitmap->AlignToFourByte(p_bitmap->GetBmiWidth());
			if (!p_bitmap->IsTopDown()) {
				rowSeek *= -1;
			}

			switch (ddsd.ddpfPixelFormat.dwRGBBitCount) {
			case 8: {
				for (MxS32 y = 0; y < heightAbs; y++) {
					memcpy(surfaceData, bitmapSrcPtr, widthNormal);
					bitmapSrcPtr += rowSeek;
					surfaceData = (MxU16*) ((MxU8*) surfaceData + newPitch);
				}

				surface->Unlock(ddsd.lpSurface);

				if (p_transparent && surface) {
					DDCOLORKEY key;
					key.dwColorSpaceLowValue = key.dwColorSpaceHighValue = 0;
					surface->SetColorKey(DDCKEY_SRCBLT, &key);
				}
				break;
			}
			case 16: {
				if (m_16bitPal == NULL) {
					goto error;
				}

				rowSeek -= widthNormal;
				newPitch -= 2 * widthNormal;

				if (p_transparent) {
					for (MxS32 y = 0; y < heightAbs; y++) {
						for (MxS32 x = 0; x < widthNormal; x++) {
							if (*bitmapSrcPtr == NULL) {
								*surfaceData = 31775;
							}
							else {
								*surfaceData = m_16bitPal[*bitmapSrcPtr];
							}

							bitmapSrcPtr++;
							surfaceData++;
						}

						bitmapSrcPtr += rowSeek;
						surfaceData = (MxU16*) ((MxU8*) surfaceData + newPitch);
					}

					DDCOLORKEY key;
					key.dwColorSpaceLowValue = key.dwColorSpaceHighValue = 31775;
					surface->SetColorKey(DDCKEY_SRCBLT, &key);
				}
				else {
					for (MxS32 y = 0; y < heightAbs; y++) {
						for (MxS32 x = 0; x < widthNormal; x++) {
							*surfaceData++ = m_16bitPal[*bitmapSrcPtr++];
						}

						bitmapSrcPtr += rowSeek;
						surfaceData = (MxU16*) ((MxU8*) surfaceData + newPitch);
					}
				}

				surface->Unlock(ddsd.lpSurface);
				break;
			}
			}
		}
	}

	return surface;

error:
	if (surface) {
		surface->Release();
	}

	return NULL;
}

// FUNCTION: LEGO1 0x100bbfb0
LPDIRECTDRAWSURFACE MxDisplaySurface::CopySurface(LPDIRECTDRAWSURFACE p_src)
{
	LPDIRECTDRAWSURFACE newSurface = NULL;
	IDirectDraw* draw = MVideoManager()->GetDirectDraw();

	DDSURFACEDESC ddsd;
	memset(&ddsd, 0, sizeof(ddsd));
	ddsd.dwSize = sizeof(ddsd);

	p_src->GetSurfaceDesc(&ddsd);

	if (draw->CreateSurface(&ddsd, &newSurface, NULL) != DD_OK) {
		return NULL;
	}

	RECT rect = {0, 0, (LONG) ddsd.dwWidth, (LONG) ddsd.dwHeight};

	if (newSurface->BltFast(0, 0, p_src, &rect, 16) != DD_OK) {
		newSurface->Release();
		return NULL;
	}

	return newSurface;
}

// FUNCTION: LEGO1 0x100bc070
LPDIRECTDRAWSURFACE MxDisplaySurface::CreateCursorSurface()
{
	LPDIRECTDRAWSURFACE newSurface = NULL;
	IDirectDraw* draw = MVideoManager()->GetDirectDraw();
	MVideoManager();

	DDSURFACEDESC ddsd;
	memset(&ddsd, 0, sizeof(ddsd));
	ddsd.dwSize = sizeof(ddsd);

	if (draw->GetDisplayMode(&ddsd) != DD_OK) {
		return NULL;
	}

	if (ddsd.ddpfPixelFormat.dwRGBBitCount != 16) {
		return NULL;
	}

	ddsd.dwWidth = 16;
	ddsd.dwHeight = 16;
	ddsd.dwFlags = DDSD_PIXELFORMAT | DDSD_WIDTH | DDSD_HEIGHT | DDSD_CAPS;
	ddsd.ddsCaps.dwCaps = DDSCAPS_VIDEOMEMORY | DDSCAPS_OFFSCREENPLAIN;

	if (draw->CreateSurface(&ddsd, &newSurface, NULL) != DD_OK) {
		ddsd.ddsCaps.dwCaps &= ~DDSCAPS_VIDEOMEMORY;
		ddsd.ddsCaps.dwCaps |= DDSCAPS_SYSTEMMEMORY;

		if (draw->CreateSurface(&ddsd, &newSurface, NULL) != DD_OK) {
			goto done;
		}
	}

	memset(&ddsd, 0, sizeof(ddsd));
	ddsd.dwSize = sizeof(ddsd);

	if (newSurface->Lock(NULL, &ddsd, DDLOCK_WAIT, NULL) != DD_OK) {
		goto done;
	}
	else {
		MxU16* surface = (MxU16*) ddsd.lpSurface;
		MxLong pitch = ddsd.lPitch;

		// draw a simple cursor to the surface
		for (MxS32 x = 0; x < 16; x++) {
			MxU16* surface2 = surface;
			for (MxS32 y = 0; y < 16; y++) {
				if ((y > 10 || x) && (x > 10 || y) && x + y != 10) {
					if (x + y > 10) {
						*surface2 = 31775;
					}
					else {
						*surface2 = -1;
					}
				}
				else {
					*surface2 = 0;
				}
				surface2++;
			}
			surface = (MxU16*) ((MxU8*) surface + pitch);
		}

		newSurface->Unlock(ddsd.lpSurface);
		DDCOLORKEY colorkey;
		colorkey.dwColorSpaceHighValue = 31775;
		colorkey.dwColorSpaceLowValue = 31775;
		newSurface->SetColorKey(DDCKEY_SRCBLT, &colorkey);

		return newSurface;
	}

done:
	if (newSurface) {
		newSurface->Release();
	}

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
