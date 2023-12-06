#include "mxstillpresenter.h"

#include "decomp.h"
#include "define.h"
#include "legoomni.h"
#include "mxomni.h"
#include "mxvideomanager.h"

DECOMP_SIZE_ASSERT(MxStillPresenter, 0x6c);

// GLOBAL: LEGO1 0x10101eb0
const char* g_strBMP_ISMAP = "BMP_ISMAP";

// FUNCTION: LEGO1 0x10043550
// MxStillPresenter::~MxStillPresenter

// FUNCTION: LEGO1 0x100435b0
void MxStillPresenter::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x100435c0
// MxStillPresenter::ClassName

// FUNCTION: LEGO1 0x100435d0
// MxStillPresenter::IsA

// SYNTHETIC: LEGO1 0x100436e0
// MxStillPresenter::`scalar deleting destructor'

// FUNCTION: LEGO1 0x100b9c70
void MxStillPresenter::Destroy(MxBool p_fromDestructor)
{
	m_criticalSection.Enter();

	if (m_bitmapInfo)
		delete m_bitmapInfo;
	m_bitmapInfo = NULL;

	m_criticalSection.Leave();

	if (!p_fromDestructor)
		MxVideoPresenter::Destroy(FALSE);
}

// FUNCTION: LEGO1 0x100b9cc0
void MxStillPresenter::LoadHeader(MxStreamChunk* p_chunk)
{
	if (m_bitmapInfo)
		delete m_bitmapInfo;

	MxU8* data = new MxU8[p_chunk->GetLength()];
	m_bitmapInfo = (MxBITMAPINFO*) data;
	memcpy(m_bitmapInfo, p_chunk->GetData(), p_chunk->GetLength());
}

// FUNCTION: LEGO1 0x100b9d10
void MxStillPresenter::CreateBitmap()
{
	if (m_bitmap)
		delete m_bitmap;

	m_bitmap = new MxBitmap;
	m_bitmap->ImportBitmapInfo(m_bitmapInfo);

	delete m_bitmapInfo;
	m_bitmapInfo = NULL;
}

// FUNCTION: LEGO1 0x100b9db0
void MxStillPresenter::NextFrame()
{
	MxStreamChunk* chunk = NextChunk();
	LoadFrame(chunk);
	m_subscriber->FUN_100b8390(chunk);
}

// FUNCTION: LEGO1 0x100b9dd0
void MxStillPresenter::LoadFrame(MxStreamChunk* p_chunk)
{
	memcpy(m_bitmap->GetBitmapData(), p_chunk->GetData(), p_chunk->GetLength());

	MxS32 height = GetHeight() - 1;
	MxS32 width = GetWidth() - 1;
	MxS32 x = GetLocationX();
	MxS32 y = GetLocationY();

	MxRect32 rect(x, y, width + x, height + y);
	MVideoManager()->InvalidateRect(rect);

	if (m_flags & Flag_Bit2) {
		undefined4 unk = 0;
		m_unk58 = MxOmni::GetInstance()->GetVideoManager()->GetDisplaySurface()->vtable44(
			m_bitmap,
			&unk,
			(m_flags & Flag_Bit4) / 8,
			m_action->GetFlags() & MxDSAction::Flag_Bit4
		);

		if (m_alpha)
			delete m_alpha;
		m_alpha = new AlphaMask(*m_bitmap);

		if (m_bitmap)
			delete m_bitmap;
		m_bitmap = NULL;

		if (m_unk58 && unk)
			m_flags |= Flag_Bit3;
		else
			m_flags &= ~Flag_Bit3;
	}
}

// STUB: LEGO1 0x100b9f30
void MxStillPresenter::VTable0x70()
{
	// TODO
}

// STUB: LEGO1 0x100b9f60
void MxStillPresenter::StartingTickle()
{
	// TODO
}

// STUB: LEGO1 0x100b9f90
void MxStillPresenter::StreamingTickle()
{
	// TODO
}

// STUB: LEGO1 0x100b9ff0
void MxStillPresenter::RepeatingTickle()
{
	// TODO
}

// STUB: LEGO1 0x100ba040
void MxStillPresenter::VTable0x88(undefined4, undefined4)
{
	// TODO
}

// STUB: LEGO1 0x100ba140
void MxStillPresenter::Enable(MxBool p_enable)
{
	// TODO
}

// FUNCTION: LEGO1 0x100ba1e0
void MxStillPresenter::ParseExtra()
{
	MxPresenter::ParseExtra();

	if (m_action->GetFlags() & MxDSAction::Flag_Bit5)
		m_flags |= Flag_Bit4;

	MxU32 len = m_action->GetExtraLength();

	if (len == 0)
		return;

	len &= MAXWORD;

	char buf[512];
	memcpy(buf, m_action->GetExtraData(), len);
	buf[len] = '\0';

	char output[512];
	if (KeyValueStringParse(output, g_strVISIBILITY, buf)) {
		if (strcmpi(output, "FALSE") == 0) {
			Enable(FALSE);
		}
	}

	if (KeyValueStringParse(output, g_strBMP_ISMAP, buf)) {
		m_flags |= Flag_Bit5;
		m_flags &= ~Flag_Bit2;
		m_flags &= ~Flag_Bit3;
	}
}

// STUB: LEGO1 0x100ba2c0
MxStillPresenter* MxStillPresenter::Clone()
{
	// TODO
	return NULL;
}
