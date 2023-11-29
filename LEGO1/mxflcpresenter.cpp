#include "mxflcpresenter.h"

#include "decomp.h"
#include "mxbitmap.h"
#include "mxomni.h"
#include "mxpalette.h"
#include "mxvideomanager.h"

DECOMP_SIZE_ASSERT(MxFlcPresenter, 0x68);

// OFFSET: LEGO1 0x100b3310
MxFlcPresenter::MxFlcPresenter()
{
	this->m_flicHeader = NULL;
	this->m_flags &= 0xfd;
	this->m_flags &= 0xfb;
}

// OFFSET: LEGO1 0x100b3420
MxFlcPresenter::~MxFlcPresenter()
{
	if (this->m_flicHeader) {
		delete this->m_flicHeader;
	}
}

// OFFSET: LEGO1 0x100b3490
void MxFlcPresenter::LoadHeader(MxStreamChunk* p_chunk)
{
	m_flicHeader = (FLIC_HEADER*) new MxU8[p_chunk->GetLength()];
	memcpy(m_flicHeader, p_chunk->GetData(), p_chunk->GetLength());
}

// OFFSET: LEGO1 0x100b34d0
void MxFlcPresenter::CreateBitmap()
{
	if (m_bitmap)
		delete m_bitmap;

	m_bitmap = new MxBitmap;
	m_bitmap->SetSize(m_flicHeader->width, m_flicHeader->height, NULL, FALSE);
}

// OFFSET: LEGO1 0x100b3620
void MxFlcPresenter::VTable0x70()
{
	MxPalette* pal = m_bitmap->CreatePalette();
	MVideoManager()->RealizePalette(pal);

	if (pal)
		delete pal;
}
