#include "legoflctexturepresenter.h"

#include "misc.h"
#include "misc/legocontainer.h"
#include "mxdsaction.h"

#include <assert.h>

DECOMP_SIZE_ASSERT(LegoFlcTexturePresenter, 0x70)

// FUNCTION: LEGO1 0x1005de80
LegoFlcTexturePresenter::LegoFlcTexturePresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x1005df70
void LegoFlcTexturePresenter::Init()
{
	m_rectCount = 0;
	m_texture = NULL;
}

// FUNCTION: LEGO1 0x1005df80
// FUNCTION: BETA10 0x100833a7
void LegoFlcTexturePresenter::StartingTickle()
{
	MxU16 extraLength;
	char* pp;
	char extraCopy[128];
	m_action->GetExtra(extraLength, pp);
	assert(pp);

	if (pp != NULL) {
		strcpy(extraCopy, pp);
		strcat(extraCopy, ".gif");
		LegoTextureContainer* textureContainer = TextureContainer();
		assert(textureContainer);
		m_texture = textureContainer->Get(extraCopy);
	}

	MxFlcPresenter::StartingTickle();
}

// FUNCTION: LEGO1 0x1005e0c0
// FUNCTION: BETA10 0x100834ce
void LegoFlcTexturePresenter::LoadFrame(MxStreamChunk* p_chunk)
{
	MxU8* data = p_chunk->GetData();

	m_rectCount = *(MxS32*) data;
	data += sizeof(MxS32);

	MxRect32* rects = (MxRect32*) data;
	data += m_rectCount * sizeof(MxRect32);

	MxBool decodedColorMap;
	DecodeFLCFrame(
		&m_frameBitmap->GetBitmapInfo()->m_bmiHeader,
		m_frameBitmap->GetImage(),
		m_flcHeader,
		(FLIC_FRAME*) data,
		&decodedColorMap
	);
}

// FUNCTION: LEGO1 0x1005e100
// FUNCTION: BETA10 0x10083562
void LegoFlcTexturePresenter::PutFrame()
{
	if (m_texture != NULL && m_rectCount != 0) {
		m_texture->LoadBits(m_frameBitmap->GetImage());
		m_rectCount = 0;
	}
}
