#include "mxflcpresenter.h"

#include "decomp.h"
#include "mxbitmap.h"
#include "mxomni.h"
#include "mxpalette.h"
#include "mxvideomanager.h"

DECOMP_SIZE_ASSERT(MxFlcPresenter, 0x68);

// FUNCTION: LEGO1 0x100b3310
MxFlcPresenter::MxFlcPresenter()
{
	this->m_flicHeader = NULL;
	this->m_flags &= ~Flag_Bit2;
	this->m_flags &= ~Flag_Bit3;
}

// FUNCTION: LEGO1 0x100b3420
MxFlcPresenter::~MxFlcPresenter()
{
	if (this->m_flicHeader) {
		delete this->m_flicHeader;
	}
}

// FUNCTION: LEGO1 0x100b3490
void MxFlcPresenter::LoadHeader(MxStreamChunk* p_chunk)
{
	m_flicHeader = (FLIC_HEADER*) new MxU8[p_chunk->GetLength()];
	memcpy(m_flicHeader, p_chunk->GetData(), p_chunk->GetLength());
}

// FUNCTION: LEGO1 0x100b34d0
void MxFlcPresenter::CreateBitmap()
{
	if (m_bitmap)
		delete m_bitmap;

	m_bitmap = new MxBitmap;
	m_bitmap->SetSize(m_flicHeader->width, m_flicHeader->height, NULL, FALSE);
}

// FUNCTION: LEGO1 0x100b3620
void MxFlcPresenter::RealizePalette()
{
	MxPalette* palette = m_bitmap->CreatePalette();
	MVideoManager()->RealizePalette(palette);
	delete palette;
}
