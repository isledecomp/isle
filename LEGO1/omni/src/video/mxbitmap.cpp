#include "mxbitmap.h"

#include "decomp.h"
#include "mxutilities.h"

DECOMP_SIZE_ASSERT(MxBitmap, 0x20);
DECOMP_SIZE_ASSERT(MxBITMAPINFO, 0x428);

// Bitmap header magic string "BM" (42 4d)
// Sources: https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapfileheader, DirectX Complete
// (1998) GLOBAL: LEGO1 0x10102184
MxU16 g_bitmapSignature = TWOCC('B', 'M');

// FUNCTION: LEGO1 0x100bc980
MxBitmap::MxBitmap()
{
	this->m_info = NULL;
	this->m_bmiHeader = NULL;
	this->m_paletteData = NULL;
	this->m_data = NULL;
	this->m_isHighColor = FALSE;
	this->m_palette = NULL;
}

// FUNCTION: LEGO1 0x100bca10
MxBitmap::~MxBitmap()
{
	if (this->m_info) {
		delete m_info;
	}
	if (this->m_data) {
		delete m_data;
	}
	if (this->m_palette) {
		delete m_palette;
	}
}

// FUNCTION: LEGO1 0x100bcaa0
MxResult MxBitmap::SetSize(MxS32 p_width, MxS32 p_height, MxPalette* p_palette, MxBool p_isHighColor)
{
	MxResult ret = FAILURE;
	MxLong size = AlignToFourByte(p_width) * p_height;

	m_info = new MxBITMAPINFO;
	if (m_info) {
		m_data = new MxU8[size];
		if (m_data) {
			m_bmiHeader = &m_info->m_bmiHeader;
			m_paletteData = m_info->m_bmiColors;
			memset(&m_info->m_bmiHeader, 0, sizeof(m_info->m_bmiHeader));

			m_bmiHeader->biSize = sizeof(*m_bmiHeader); // should be 40 bytes
			m_bmiHeader->biWidth = p_width;
			m_bmiHeader->biHeight = p_height;
			m_bmiHeader->biPlanes = 1;
			m_bmiHeader->biBitCount = 8;
			m_bmiHeader->biCompression = 0;
			m_bmiHeader->biSizeImage = size;

			if (!ImportColorsToPalette(m_paletteData, p_palette)) {
				if (!SetBitDepth(p_isHighColor)) {
					ret = SUCCESS;
				}
			}
		}
	}

	if (ret) {
		if (m_info) {
			delete m_info;
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
MxResult MxBitmap::ImportBitmapInfo(MxBITMAPINFO* p_info)
{
	MxResult result = FAILURE;
	MxLong width = p_info->m_bmiHeader.biWidth;
	MxLong height = p_info->m_bmiHeader.biHeight;
	MxLong size = AlignToFourByte(width) * height;

	this->m_info = new MxBITMAPINFO;
	if (this->m_info) {
		this->m_data = new MxU8[size];
		if (this->m_data) {
			memcpy(this->m_info, p_info, sizeof(*this->m_info));
			this->m_bmiHeader = &this->m_info->m_bmiHeader;
			this->m_paletteData = this->m_info->m_bmiColors;
			result = SUCCESS;
		}
	}

	if (result != SUCCESS) {
		if (this->m_info) {
			delete this->m_info;
			this->m_info = NULL;
		}

		if (this->m_data) {
			delete[] this->m_data;
			this->m_data = NULL;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100bcc40
MxResult MxBitmap::ImportBitmap(MxBitmap* p_bitmap)
{
	MxResult result = FAILURE;

	this->m_info = new MxBITMAPINFO;
	if (this->m_info) {
		this->m_data = new MxU8[p_bitmap->GetDataSize()];
		if (this->m_data) {
			memcpy(this->m_info, p_bitmap->GetBitmapInfo(), MxBITMAPINFO::Size());
			memcpy(this->m_data, p_bitmap->GetBitmapData(), p_bitmap->GetDataSize());

			this->m_bmiHeader = &this->m_info->m_bmiHeader;
			this->m_paletteData = this->m_info->m_bmiColors;
			result = SUCCESS;
		}
	}

	if (result != SUCCESS) {
		if (this->m_info) {
			delete this->m_info;
			this->m_info = NULL;
		}

		if (this->m_data) {
			delete this->m_data;
			this->m_data = NULL;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100bcd10
MxLong MxBitmap::Read(const char* p_filename)
{
	MxResult result = FAILURE;
	HANDLE handle =
		CreateFileA(p_filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (handle != INVALID_HANDLE_VALUE && !LoadFile(handle)) {
		result = SUCCESS;
	}

	if (handle) {
		CloseHandle(handle);
	}

	return result;
}

// FUNCTION: LEGO1 0x100bcd60
MxResult MxBitmap::LoadFile(HANDLE p_handle)
{
	MxResult result = FAILURE;
	DWORD bytesRead;
	BITMAPFILEHEADER hdr;

	BOOL ret = ReadFile(p_handle, &hdr, sizeof(hdr), &bytesRead, NULL);
	if (ret && (hdr.bfType == g_bitmapSignature)) {
		this->m_info = new MxBITMAPINFO;
		if (this->m_info) {
			ret = ReadFile(p_handle, this->m_info, sizeof(*this->m_info), &bytesRead, NULL);
			if (ret && (this->m_info->m_bmiHeader.biBitCount == 8)) {
				MxLong size = hdr.bfSize - (sizeof(MxBITMAPINFO) + sizeof(BITMAPFILEHEADER));
				this->m_data = new MxU8[size];
				if (this->m_data) {
					ret = ReadFile(p_handle, this->m_data, size, &bytesRead, NULL);
					if (ret) {
						this->m_bmiHeader = &this->m_info->m_bmiHeader;
						this->m_paletteData = this->m_info->m_bmiColors;
						if (this->m_info->m_bmiHeader.biSizeImage == 0) {
							MxLong height = AbsFlipped(this->m_info->m_bmiHeader.biHeight);
							this->m_info->m_bmiHeader.biSizeImage =
								AlignToFourByte(this->m_info->m_bmiHeader.biWidth) * height;
						}
						result = SUCCESS;
					}
				}
			}
		}
	}

	if (result != SUCCESS) {
		if (this->m_info) {
			delete this->m_info;
			this->m_info = NULL;
		}

		if (this->m_data) {
			delete this->m_data;
			this->m_data = NULL;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100bce70
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
	MxLong dstHeight = GetBmiHeightAbs();
	MxLong srcHeight = p_src->GetBmiHeightAbs();

	if (GetRectIntersection(
			p_src->GetBmiWidth(),
			srcHeight,
			GetBmiWidth(),
			dstHeight,
			&p_srcLeft,
			&p_srcTop,
			&p_dstLeft,
			&p_dstTop,
			&p_width,
			&p_height
		)) {
		MxU8* srcStart = p_src->GetStart(p_srcLeft, p_srcTop);
		MxU8* dstStart = GetStart(p_dstLeft, p_dstTop);
		MxLong srcStride = p_src->GetAdjustedStride();
		MxLong dstStride = GetAdjustedStride();

		while (p_height--) {
			memcpy(dstStart, srcStart, p_width);
			dstStart += dstStride;
			srcStart += srcStride;
		}
	}
}

// FUNCTION: LEGO1 0x100bd020
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
	MxLong dstHeight = GetBmiHeightAbs();
	MxLong srcHeight = p_src->GetBmiHeightAbs();

	if (GetRectIntersection(
			p_src->GetBmiWidth(),
			srcHeight,
			GetBmiWidth(),
			dstHeight,
			&p_srcLeft,
			&p_srcTop,
			&p_dstLeft,
			&p_dstTop,
			&p_width,
			&p_height
		)) {
		MxU8* srcStart = p_src->GetStart(p_srcLeft, p_srcTop);
		MxU8* dstStart = GetStart(p_dstLeft, p_dstTop);
		MxLong srcStride = p_src->GetAdjustedStride() - p_width;
		MxLong dstStride = GetAdjustedStride() - p_width;

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
}

// FUNCTION: LEGO1 0x100bd1c0
MxPalette* MxBitmap::CreatePalette()
{
	MxBool success = FALSE;
	MxPalette* palette = NULL;

	switch (this->m_isHighColor) {
	case FALSE:
		palette = new MxPalette(this->m_paletteData);

		if (!palette) {
			goto done;
		}

		break;
	case TRUE:
		palette = this->m_palette->Clone();

		if (!palette) {
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
void MxBitmap::ImportPalette(MxPalette* p_palette)
{
	// Odd to use a switch on a boolean, but it matches.
	switch (this->m_isHighColor) {
	case FALSE:
		ImportColorsToPalette(this->m_paletteData, p_palette);
		break;

	case TRUE:
		if (this->m_palette) {
			delete this->m_palette;
		}
		this->m_palette = p_palette->Clone();
		break;
	}
}

// FUNCTION: LEGO1 0x100bd2d0
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
		if (m_palette) {
			delete m_palette;
		}

		m_palette = NULL;
		break;
	case TRUE: {
		pal = NULL;
		pal = new MxPalette(m_paletteData);

		if (!pal) {
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
	if ((this->m_bmiHeader->biCompression != BI_RGB_TOPDOWN) && (0 < this->m_bmiHeader->biHeight)) {
		p_ySrc = (this->m_bmiHeader->biHeight - p_destHeight) - p_ySrc;
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
		this->m_data,
		(BITMAPINFO*) this->m_info,
		this->m_isHighColor,
		SRCCOPY
	);
}

// FUNCTION: LEGO1 0x100bd450
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
