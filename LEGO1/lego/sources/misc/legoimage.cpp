#include "legoimage.h"

#include "decomp.h"
#include "legostorage.h"
#include "memory.h"

DECOMP_SIZE_ASSERT(LegoPaletteEntry, 0x03);
DECOMP_SIZE_ASSERT(LegoImage, 0x310);

// FUNCTION: LEGO1 0x100994c0
LegoPaletteEntry::LegoPaletteEntry()
{
	m_red = 0;
	m_green = 0;
	m_blue = 0;
}

// FUNCTION: LEGO1 0x100994d0
LegoResult LegoPaletteEntry::Read(LegoStorage* p_storage)
{
	LegoResult result;
	if ((result = p_storage->Read(&m_red, sizeof(m_red))) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Read(&m_green, sizeof(m_green))) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Read(&m_blue, sizeof(m_blue))) != SUCCESS) {
		return result;
	}
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10099520
LegoResult LegoPaletteEntry::Write(LegoStorage* p_storage)
{
	LegoResult result;
	if ((result = p_storage->Write(&m_red, sizeof(m_red))) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Write(&m_green, sizeof(m_green))) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Write(&m_blue, sizeof(m_blue))) != SUCCESS) {
		return result;
	}
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10099570
LegoImage::LegoImage()
{
	m_width = 0;
	m_height = 0;
	m_count = 0;
	m_bits = NULL;
}

// FUNCTION: LEGO1 0x100995a0
LegoImage::LegoImage(LegoU32 p_width, LegoU32 p_height)
{
	m_width = p_width;
	m_height = p_height;
	m_count = 0;
	m_bits = new LegoU8[m_width * m_height];
}

// FUNCTION: LEGO1 0x100995f0
LegoImage::~LegoImage()
{
	if (m_bits) {
		delete[] m_bits;
	}
}

// FUNCTION: LEGO1 0x10099610
LegoResult LegoImage::Read(LegoStorage* p_storage, LegoU32 p_square)
{
	LegoResult result;
	if ((result = p_storage->Read(&m_width, sizeof(m_width))) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Read(&m_height, sizeof(m_height))) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Read(&m_count, sizeof(m_height))) != SUCCESS) {
		return result;
	}
	for (LegoU32 i = 0; i < m_count; i++) {
		if ((result = m_palette[i].Read(p_storage)) != SUCCESS) {
			return result;
		}
	}
	if (m_bits) {
		delete[] m_bits;
	}
	m_bits = new LegoU8[m_width * m_height];
	if ((result = p_storage->Read(m_bits, m_width * m_height)) != SUCCESS) {
		return result;
	}

	if (p_square && m_width != m_height) {
		LegoU8* newBits;

		if (m_height < m_width) {
			LegoU32 aspect = m_width / m_height;
			newBits = new LegoU8[m_width * m_width];
			LegoU8* src = m_bits;
			LegoU8* dst = newBits;

			for (LegoU32 row = 0; row < m_height; row++) {
				if (aspect) {
					for (LegoU32 dup = aspect; dup; dup--) {
						memcpy(dst, src, m_width);
						dst += m_width;
					}
				}
				src += m_width;
			}

			m_height = m_width;
		}
		else {
			LegoU32 aspect = m_height / m_width;
			newBits = new LegoU8[m_height * m_height];
			LegoU8* src = m_bits;
			LegoU8* dst = newBits;

			for (LegoU32 row = 0; row < m_height; row++) {
				for (LegoU32 col = 0; col < m_width; col++) {
					if (aspect) {
						for (LegoU32 dup = aspect; dup; dup--) {
							*dst = *src;
							dst++;
						}
					}

					src++;
				}
			}

			m_width = m_height;
		}

		delete[] m_bits;
		m_bits = newBits;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100997e0
LegoResult LegoImage::Write(LegoStorage* p_storage)
{
	LegoResult result;
	if ((result = p_storage->Write(&m_width, sizeof(m_width))) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Write(&m_height, sizeof(m_height))) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Write(&m_count, sizeof(m_height))) != SUCCESS) {
		return result;
	}
	for (LegoU32 i = 0; i < m_count; i++) {
		if ((result = m_palette[i].Write(p_storage)) != SUCCESS) {
			return result;
		}
	}
	if (m_bits) {
		if ((result = p_storage->Write(m_bits, m_width * m_height)) != SUCCESS) {
			return result;
		}
	}
	return SUCCESS;
}
