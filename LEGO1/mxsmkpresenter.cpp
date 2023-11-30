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

	FUN_100c5d40(&m_mxSmack);
	Init();

	m_criticalSection.Leave();

	if (!p_fromDestructor) {
		MxVideoPresenter::Destroy(FALSE);
	}
}

// STUB: LEGO1 0x100b3940
void MxSmkPresenter::LoadHeader(MxStreamChunk* p_chunk)
{
	// TODO
}

// FUNCTION: LEGO1 0x100b3960
void MxSmkPresenter::CreateBitmap()
{
	if (m_bitmap)
		delete m_bitmap;

	m_bitmap = new MxBitmap;
	m_bitmap->SetSize(m_mxSmack.m_smack.m_width, m_mxSmack.m_smack.m_height, NULL, FALSE);
}

// STUB: LEGO1 0x100b3a00
void MxSmkPresenter::LoadFrame(MxStreamChunk* p_chunk)
{
	// TODO
}

// FUNCTION: LEGO1 0x100b4260
MxU32 MxSmkPresenter::VTable0x88()
{
	MxU32 result = m_unk0x71c;
	if ((m_mxSmack.m_smack.m_smkType & 1) != 0) {
		result = m_unk0x71c / m_mxSmack.m_smack.m_frames;
		if (1 < m_unk0x71c && (m_unk0x71c % m_mxSmack.m_smack.m_frames) == 1) {
			m_unk0x71c = 1;
		}
		return result;
	}
	else {
		if (m_mxSmack.m_smack.m_frames == result) {
			m_unk0x71c = 0;
			result = 0;
			memset(m_mxSmack.m_smack.m_palette, 0, sizeof(m_mxSmack.m_smack.m_palette));
		}
		return result;
	}
}

// FUNCTION: LEGO1 0x100b42c0
void MxSmkPresenter::VTable0x70()
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

// FUNCTION: LEGO1 0x100c5d40
void MxSmkPresenter::FUN_100c5d40(MxSmack* p_mxSmack)
{
	if (p_mxSmack->m_unk0x6a0)
		delete p_mxSmack->m_unk0x6a0;
	if (p_mxSmack->m_unk0x6a4)
		delete p_mxSmack->m_unk0x6a4;
	if (p_mxSmack->m_unk0x6a8)
		delete p_mxSmack->m_unk0x6a8;
	if (p_mxSmack->m_unk0x6ac)
		delete p_mxSmack->m_unk0x6ac;
	if (p_mxSmack->m_unk0x6b4)
		delete p_mxSmack->m_unk0x6b4;
}
