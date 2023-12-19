#include "mxsmkpresenter.h"

#include "decomp.h"
#include "mxvideomanager.h"

DECOMP_SIZE_ASSERT(MxSmkPresenter, 0x720);

// FUNCTION: LEGO1 0x100b3650
MxSmkPresenter::MxSmkPresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x100b3870
MxSmkPresenter::~MxSmkPresenter()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x100b38d0
void MxSmkPresenter::Init()
{
	m_unk0x71c = 0;
	memset(&m_mxSmack, 0, sizeof(m_mxSmack));
	m_flags &= 0xfd;
	m_flags &= 0xfb;
}

// FUNCTION: LEGO1 0x100b3900
void MxSmkPresenter::Destroy(MxBool p_fromDestructor)
{
	m_criticalSection.Enter();

	MxSmack::Destroy(&m_mxSmack);
	Init();

	m_criticalSection.Leave();

	if (!p_fromDestructor) {
		MxVideoPresenter::Destroy(FALSE);
	}
}

// FUNCTION: LEGO1 0x100b3940
void MxSmkPresenter::LoadHeader(MxStreamChunk* p_chunk)
{
	MxSmack::LoadHeaderAndTrees(p_chunk->GetData(), &m_mxSmack);
}

// FUNCTION: LEGO1 0x100b3960
void MxSmkPresenter::CreateBitmap()
{
	if (m_bitmap)
		delete m_bitmap;

	m_bitmap = new MxBitmap;
	m_bitmap->SetSize(m_mxSmack.m_smackTag.Width, m_mxSmack.m_smackTag.Height, NULL, FALSE);
}

// STUB: LEGO1 0x100b3a00
void MxSmkPresenter::LoadFrame(MxStreamChunk* p_chunk)
{
	// TODO
}

// FUNCTION: LEGO1 0x100b4260
void MxSmkPresenter::VTable0x88()
{
	if ((m_mxSmack.m_smackTag.SmackerType & 1) != 0) {
		MxU32 und = (m_unk0x71c % m_mxSmack.m_smackTag.Frames);
		if (1 < m_unk0x71c && und == 1)
			m_unk0x71c = 1;
	}
	else {
		if (m_mxSmack.m_smackTag.Frames == m_unk0x71c) {
			m_unk0x71c = 0;
			// TODO: struct incorrect, Palette at wrong offset?
			memset(m_mxSmack.m_smackTag.Palette, 0, sizeof(m_mxSmack.m_smackTag.Palette));
		}
	}
}

// FUNCTION: LEGO1 0x100b42c0
void MxSmkPresenter::RealizePalette()
{
	MxPalette* palette = m_bitmap->CreatePalette();
	MVideoManager()->RealizePalette(palette);
	delete palette;
}

// FUNCTION: LEGO1 0x100b4300
void MxSmkPresenter::Destroy()
{
	Destroy(FALSE);
}
