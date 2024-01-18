#include "mxflcpresenter.h"

#include "decomp.h"
#include "mxbitmap.h"
#include "mxdsmediaaction.h"
#include "mxomni.h"
#include "mxpalette.h"
#include "mxvideomanager.h"

DECOMP_SIZE_ASSERT(MxFlcPresenter, 0x68);

// FUNCTION: LEGO1 0x100b3310
MxFlcPresenter::MxFlcPresenter()
{
	this->m_flcHeader = NULL;
	this->m_flags &= ~c_bit2;
	this->m_flags &= ~c_bit3;
}

// FUNCTION: LEGO1 0x100b3420
MxFlcPresenter::~MxFlcPresenter()
{
	if (this->m_flcHeader) {
		delete this->m_flcHeader;
	}
}

// FUNCTION: LEGO1 0x100b3490
void MxFlcPresenter::LoadHeader(MxStreamChunk* p_chunk)
{
	m_flcHeader = (FLIC_HEADER*) new MxU8[p_chunk->GetLength()];
	memcpy(m_flcHeader, p_chunk->GetData(), p_chunk->GetLength());
}

// FUNCTION: LEGO1 0x100b34d0
void MxFlcPresenter::CreateBitmap()
{
	if (m_bitmap)
		delete m_bitmap;

	m_bitmap = new MxBitmap;
	m_bitmap->SetSize(m_flcHeader->width, m_flcHeader->height, NULL, FALSE);
}

// FUNCTION: LEGO1 0x100b3570
void MxFlcPresenter::LoadFrame(MxStreamChunk* p_chunk)
{
	MxU32* dat = (MxU32*) p_chunk->GetData() + 4;
	MxU32 offset = *(MxU32*) p_chunk->GetData();
	MxBool decodedColorMap;

	DecodeFLCFrame(
		&m_bitmap->GetBitmapInfo()->m_bmiHeader,
		m_bitmap->GetBitmapData(),
		m_flcHeader,
		&dat[offset],
		//&(p_chunk->GetData() + 4)[*(MxU32*) p_chunk->GetData()],
		&decodedColorMap
	);

	if (((MxDSMediaAction*) m_action)->GetPaletteManagement() && decodedColorMap)
		RealizePalette();

	while (offset > 0) {
		dat += 4;
		MxRect32 rect(
			dat[-4] + m_location.GetX(),
			dat[-3] + m_location.GetY(),
			dat[-2] + m_location.GetX(),
			dat[-1] + m_location.GetY()
		);
		MVideoManager()->InvalidateRect(rect);
		offset--;
	}
}

// FUNCTION: LEGO1 0x100b3620
void MxFlcPresenter::RealizePalette()
{
	MxPalette* palette = m_bitmap->CreatePalette();
	MVideoManager()->RealizePalette(palette);
	delete palette;
}
