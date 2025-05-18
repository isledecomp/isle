#include "mxbitmap.h"

#include "decomp.h"
#include "mxpalette.h"
#include "mxutilities.h"

DECOMP_SIZE_ASSERT(MxBitmap, 0x20);
DECOMP_SIZE_ASSERT(MxBITMAPINFO, 0x428);

DECOMP_SIZE_ASSERT(BITMAPFILEHEADER, 0xe);

// GLOBAL: LEGO1 0x10102184
// GLOBAL: BETA10 0x10203030
MxU16 g_bitmapSignature = TWOCC('B', 'M');

// FUNCTION: LEGO1 0x100bc980
// FUNCTION: BETA10 0x1013cab0
MxBitmap::MxBitmap()
{
	m_info = NULL;
	m_bmiHeader = NULL;
	m_paletteData = NULL;
	m_data = NULL;
	m_isHighColor = FALSE;
	m_palette = NULL;
}

// FUNCTION: LEGO1 0x100bca10
// FUNCTION: BETA10 0x1013cb58
MxBitmap::~MxBitmap()
{
	if (m_info) {
		delete[] ((MxU8*) m_info);
	}
	if (m_data) {
		delete[] m_data;
	}
	if (m_palette) {
		delete m_palette;
	}
}

// FUNCTION: LEGO1 0x100bcaa0
// FUNCTION: BETA10 0x1013cc47
MxResult MxBitmap::SetSize(MxS32 p_width, MxS32 p_height, MxPalette* p_palette, MxBool p_isHighColor)
{
	MxResult ret = FAILURE;
	MxLong size = AlignToFourByte(p_width) * p_height;

	m_info = (MxBITMAPINFO*) new MxU8[MxBitmapInfoSize()];
	if (!m_info) {
		goto done;
	}

	m_data = new MxU8[size];
	if (!m_data) {
		goto done;
	}

	m_bmiHeader = &m_info->m_bmiHeader;
	m_paletteData = m_info->m_bmiColors;
	memset(m_bmiHeader, 0, sizeof(m_info->m_bmiHeader));

	m_bmiHeader->biSize = sizeof(*m_bmiHeader); // should be 40 bytes
	m_bmiHeader->biWidth = p_width;
	m_bmiHeader->biHeight = p_height;
	m_bmiHeader->biPlanes = 1;
	m_bmiHeader->biBitCount = 8;
	m_bmiHeader->biCompression = 0;
	m_bmiHeader->biSizeImage = size;

	if (ImportColorsToPalette(m_paletteData, p_palette)) {
		goto done;
	}

	if (SetBitDepth(p_isHighColor)) {
		goto done;
	}

	ret = SUCCESS;

done:
	if (ret) {
		if (m_info) {
			delete[] ((MxU8*) m_info);
			m_info = NULL;
		}

		if (m_data) {
			delete[] m_data;
			m_data = NULL;
		}
	}

	return ret;
}

// FUNCTION: LEGO1 0x100bcba0
// FUNCTION: BETA10 0x1013ce25
MxResult MxBitmap::ImportBitmapInfo(MxBITMAPINFO* p_info)
{
	MxResult result = FAILURE;
	MxLong size = AlignToFourByte(p_info->m_bmiHeader.biWidth) * p_info->m_bmiHeader.biHeight;

	m_info = (MxBITMAPINFO*) new MxU8[MxBitmapInfoSize()];
	if (!m_info) {
		goto done;
	}

	m_data = new MxU8[size];
	if (!m_data) {
		goto done;
	}

	memcpy(m_info, p_info, MxBitmapInfoSize());
	m_bmiHeader = &m_info->m_bmiHeader;
	m_paletteData = m_info->m_bmiColors;
	result = SUCCESS;

done:
	if (result != SUCCESS) {
		if (m_info) {
			delete[] ((MxU8*) m_info);
			m_info = NULL;
		}

		if (m_data) {
			delete[] m_data;
			m_data = NULL;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100bcc40
// FUNCTION: BETA10 0x1013cf6d
MxResult MxBitmap::ImportBitmap(MxBitmap* p_bitmap)
{
	MxResult result = FAILURE;

	m_info = (MxBITMAPINFO*) new MxU8[p_bitmap->MxBitmapInfoSize()];
	if (!m_info) {
		goto done;
	}

	m_data = new MxU8[p_bitmap->GetDataSize()];
	if (!m_data) {
		goto done;
	}

	memcpy(m_info, p_bitmap->GetBitmapInfo(), p_bitmap->MxBitmapInfoSize());
	memcpy(m_data, p_bitmap->GetImage(), p_bitmap->GetDataSize());

	m_bmiHeader = &m_info->m_bmiHeader;
	m_paletteData = m_info->m_bmiColors;
	result = SUCCESS;

done:
	if (result != SUCCESS) {
		if (m_info) {
			delete[] ((MxU8*) m_info);
			m_info = NULL;
		}

		if (m_data) {
			delete[] m_data;
			m_data = NULL;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100bcd10
// FUNCTION: BETA10 0x1013d0c7
MxLong MxBitmap::Read(const char* p_filename)
{
	MxResult result = FAILURE;
	HANDLE handle = 0;

	handle = CreateFile(p_filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (handle == INVALID_HANDLE_VALUE) {
		goto done;
	}

	if (LoadFile(handle)) {
		goto done;
	}

	result = SUCCESS;

done:
	if (handle) {
		CloseHandle(handle);
	}

	return result;
}

// FUNCTION: LEGO1 0x100bcd60
// FUNCTION: BETA10 0x1013d169
MxResult MxBitmap::LoadFile(HANDLE p_handle)
{
	MxResult result = FAILURE;
	MxLong unused = 0;

	MxLong size;
	DWORD bytesRead;
	BITMAPFILEHEADER hdr;
	if (!ReadFile(p_handle, &hdr, 14, &bytesRead, NULL)) {
		goto done;
	}

	if (hdr.bfType != g_bitmapSignature) {
		goto done;
	}

	m_info = (MxBITMAPINFO*) new MxU8[MxBitmapInfoSize()];
	if (!m_info) {
		goto done;
	}

	if (!ReadFile(p_handle, m_info, MxBitmapInfoSize(), &bytesRead, NULL)) {
		goto done;
	}

	if (m_info->m_bmiHeader.biBitCount != 8) {
		goto done;
	}

	size = hdr.bfSize - sizeof(BITMAPFILEHEADER) - MxBitmapInfoSize();
	m_data = new MxU8[size];
	if (!m_data) {
		goto done;
	}

	if (!ReadFile(p_handle, m_data, size, &bytesRead, NULL)) {
		goto done;
	}

	m_bmiHeader = &m_info->m_bmiHeader;
	m_paletteData = m_info->m_bmiColors;
	if (m_info->m_bmiHeader.biSizeImage == 0) {
		m_info->m_bmiHeader.biSizeImage = GetDataSize();
	}

	result = SUCCESS;

done:
	if (result != SUCCESS) {
		if (m_info) {
			delete[] ((MxU8*) m_info);
			m_info = NULL;
		}

		if (m_data) {
			delete[] m_data;
			m_data = NULL;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100bce70
// FUNCTION: BETA10 0x1013d399
void MxBitmap::BitBlt(
	MxBitmap* p_src,
	MxS32 p_srcLeft,
	MxS32 p_srcTop,
	MxS32 p_dstLeft,
	MxS32 p_dstTop,
	MxS32 p_width,
	MxS32 p_height
)
{
	if (!GetRectIntersection(
			p_src->GetBmiWidth(),
			p_src->GetBmiHeightAbs(),
			GetBmiWidth(),
			GetBmiHeightAbs(),
			&p_srcLeft,
			&p_srcTop,
			&p_dstLeft,
			&p_dstTop,
			&p_width,
			&p_height
		)) {
		return;
	}

	MxU8* srcStart = p_src->GetStart(p_srcLeft, p_srcTop);
	MxU8* dstStart = GetStart(p_dstLeft, p_dstTop);
	MxLong srcStride = GetAdjustedStride(p_src);
	MxLong dstStride = GetAdjustedStride(this);

	while (p_height--) {
		memcpy(dstStart, srcStart, p_width);
		dstStart += dstStride;
		srcStart += srcStride;
	}
}

// FUNCTION: LEGO1 0x100bd020
// FUNCTION: BETA10 0x1013d4ea
void MxBitmap::BitBltTransparent(
	MxBitmap* p_src,
	MxS32 p_srcLeft,
	MxS32 p_srcTop,
	MxS32 p_dstLeft,
	MxS32 p_dstTop,
	MxS32 p_width,
	MxS32 p_height
)
{
	if (!GetRectIntersection(
			p_src->GetBmiWidth(),
			p_src->GetBmiHeightAbs(),
			GetBmiWidth(),
			GetBmiHeightAbs(),
			&p_srcLeft,
			&p_srcTop,
			&p_dstLeft,
			&p_dstTop,
			&p_width,
			&p_height
		)) {
		return;
	}

	MxU8* srcStart = p_src->GetStart(p_srcLeft, p_srcTop);
	MxU8* dstStart = GetStart(p_dstLeft, p_dstTop);
	MxLong srcStride = -p_width + GetAdjustedStride(p_src);
	MxLong dstStride = -p_width + GetAdjustedStride(this);

	for (MxS32 h = 0; h < p_height; h++) {
		for (MxS32 w = 0; w < p_width; w++) {
			if (*srcStart) {
				*dstStart = *srcStart;
			}
			srcStart++;
			dstStart++;
		}

		srcStart += srcStride;
		dstStart += dstStride;
	}
}

// FUNCTION: LEGO1 0x100bd1c0
// FUNCTION: BETA10 0x1013d684
MxPalette* MxBitmap::CreatePalette()
{
	MxBool success = FALSE;
	MxPalette* palette = NULL;

	switch (m_isHighColor) {
	case FALSE:
		if (!(palette = new MxPalette(m_paletteData))) {
			goto done;
		}

		break;
	case TRUE:
		if (!(palette = m_palette->Clone())) {
			goto done;
		}

		break;
	default:
		goto done;
	}

	success = TRUE;

done:
	if (!success && palette) {
		delete palette;
		palette = NULL;
	}

	return palette;
}

// FUNCTION: LEGO1 0x100bd280
// FUNCTION: BETA10 0x1013d80e
void MxBitmap::ImportPalette(MxPalette* p_palette)
{
	// Odd to use a switch on a boolean, but it matches.
	switch (m_isHighColor) {
	case FALSE:
		ImportColorsToPalette(m_paletteData, p_palette);
		break;

	case TRUE:
		delete m_palette;
		m_palette = p_palette->Clone();
		break;
	}
}

// FUNCTION: LEGO1 0x100bd2d0
// FUNCTION: BETA10 0x1013d8a9
MxResult MxBitmap::SetBitDepth(MxBool p_isHighColor)
{
	MxResult ret = FAILURE;
	MxPalette* pal = NULL;

	if (m_isHighColor == p_isHighColor) {
		// no change: do nothing.
		ret = SUCCESS;
		goto done;
	}

	switch (p_isHighColor) {
	case FALSE:
		ImportColorsToPalette(m_paletteData, m_palette);
		delete m_palette;
		m_palette = NULL;
		break;
	case TRUE: {
		if (!(pal = new MxPalette(m_paletteData))) {
			goto done;
		}

		m_palette = pal;

		// TODO: what is this? zeroing out top half of palette?
		MxU16* buf = (MxU16*) m_paletteData;
		for (MxU16 i = 0; i < 256; i++) {
			buf[i] = i;
		}
		break;
	}
	default:
		goto done;
	}

	m_isHighColor = p_isHighColor;
	ret = SUCCESS;

done:
	// If we were unsuccessful overall but did manage to alloc
	// the MxPalette, free it.
	if (ret && pal) {
		delete pal;
	}

	return ret;
}

// FUNCTION: LEGO1 0x100bd3e0
// FUNCTION: BETA10 0x1013dad2
MxResult MxBitmap::StretchBits(
	HDC p_hdc,
	MxS32 p_xSrc,
	MxS32 p_ySrc,
	MxS32 p_xDest,
	MxS32 p_yDest,
	MxS32 p_destWidth,
	MxS32 p_destHeight
)
{
	// Compression fix?
	if (IsBottomUp()) {
		p_ySrc = GetBmiHeightAbs() - p_ySrc - p_destHeight;
	}

	return StretchDIBits(
		p_hdc,
		p_xDest,
		p_yDest,
		p_destWidth,
		p_destHeight,
		p_xSrc,
		p_ySrc,
		p_destWidth,
		p_destHeight,
		m_data,
		(BITMAPINFO*) m_info,
		m_isHighColor,
		SRCCOPY
	);
}

// FUNCTION: LEGO1 0x100bd450
// FUNCTION: BETA10 0x1013db55
MxResult MxBitmap::ImportColorsToPalette(RGBQUAD* p_rgbquad, MxPalette* p_palette)
{
	MxResult ret = FAILURE;
	PALETTEENTRY entries[256];

	if (p_palette) {
		if (p_palette->GetEntries(entries)) {
			goto done;
		}
	}
	else {
		MxPalette palette;
		if (palette.GetEntries(entries)) {
			goto done;
		}
	}

	MxS32 i;
	for (i = 0; i < 256; i++) {
		p_rgbquad[i].rgbRed = entries[i].peRed;
		p_rgbquad[i].rgbGreen = entries[i].peGreen;
		p_rgbquad[i].rgbBlue = entries[i].peBlue;
		p_rgbquad[i].rgbReserved = 0;
	}

	ret = SUCCESS;

done:
	return ret;
}
