#include "mximage.h"

DECOMP_SIZE_ASSERT(MxImage, 0x310)

// FUNCTION: LEGO1 0x10099570
MxImage::MxImage()
{
	m_width = 0;
	m_height = 0;
	m_colors = 0;
	m_image = NULL;
}

// FUNCTION: LEGO1 0x100995a0
MxImage::MxImage(MxU32 p_width, MxU32 p_height)
{
	m_width = p_width;
	m_height = p_height;
	m_colors = 0;
	m_image = new MxU8[p_width * p_height];
}

// FUNCTION: LEGO1 0x100995f0
MxImage::~MxImage()
{
	if (m_image)
		delete m_image;
}

// FUNCTION: LEGO1 0x10099610
MxResult MxImage::Read(LegoStream* p_stream, MxU32 p_square)
{
	MxResult result;
	if ((result = p_stream->Read(&m_width, 4)) != SUCCESS)
		return result;
	if ((result = p_stream->Read(&m_height, 4)) != SUCCESS)
		return result;
	if ((result = p_stream->Read(&m_colors, 4)) != SUCCESS)
		return result;
	for (int i = 0; i < m_colors; i++) {
		if ((result = m_palette[i].Read(p_stream)) != SUCCESS)
			return result;
	}
	if (m_image)
		delete m_image;
	m_image = new MxU8[m_width * m_height];
	if ((result = p_stream->Read(m_image, m_width * m_height)) != SUCCESS)
		return result;
	if (p_square && m_width != m_height) {
		MxU8* newImage;
		if (m_height < m_width) {
			MxU32 aspect = m_width / m_height;
			newImage = new MxU8[m_width * m_width];
			MxU8* src = m_image;
			MxU8* dst = newImage;
			for (MxU32 row = 0; row < m_height; row++) {
				for (MxU32 dup = aspect; dup; dup--) {
					memcpy(dst, src, m_width);
					dst += m_width;
				}
				src += m_width;
			}
			m_height = m_width;
		}
		else {
			MxU32 aspect = m_height / m_width;
			newImage = new MxU8[m_height * m_height];
			MxU8* src = m_image;
			MxU8* dst = newImage;
			for (MxU32 row = 0; row < m_height; row++) {
				for (MxU32 col = 0; col < m_width; col++) {
					for (MxU32 dup = aspect; dup; dup--) {
						*dst = *src;
						dst++;
					}
					src++;
				}
			}
			m_width = m_height;
		}
		delete m_image;
		m_image = newImage;
	}
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100997e0
MxResult MxImage::Write(LegoStream* p_stream)
{
	MxResult result;
	if ((result = p_stream->Write(&m_width, 4)) != SUCCESS)
		return result;
	if ((result = p_stream->Write(&m_height, 4)) != SUCCESS)
		return result;
	if ((result = p_stream->Write(&m_colors, 4)) != SUCCESS)
		return result;
	for (int i = 0; i < m_colors; i++) {
		if ((result = m_palette[i].Write(p_stream)) != SUCCESS)
			return result;
	}
	if (m_image)
		if ((result = p_stream->Write(m_image, m_width * m_height)) != SUCCESS)
			return result;
	return SUCCESS;
}
