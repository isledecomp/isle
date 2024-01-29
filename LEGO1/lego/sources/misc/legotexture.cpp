#include "legotexture.h"

#include "decomp.h"
#include "legoimage.h"
#include "legostorage.h"

DECOMP_SIZE_ASSERT(LegoTexture, 0x04);

// FUNCTION: LEGO1 0x10098fb0
LegoTexture::LegoTexture()
{
	m_image = new LegoImage();
}

// FUNCTION: LEGO1 0x10099030
LegoTexture::~LegoTexture()
{
	delete m_image;
}

// FUNCTION: LEGO1 0x10099050
LegoResult LegoTexture::Read(LegoStorage* p_storage, LegoU32 p_square)
{
	return m_image->Read(p_storage, p_square);
}

// FUNCTION: LEGO1 0x10099070
LegoResult LegoTexture::Write(LegoStorage* p_storage)
{
	return m_image->Write(p_storage);
}
