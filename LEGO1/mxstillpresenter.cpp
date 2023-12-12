#include "mxstillpresenter.h"

#include "decomp.h"
#include "define.h"
#include "legoomni.h"
#include "mxcompositepresenter.h"
#include "mxdsmediaaction.h"
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
	MxS32 x = m_location.m_x;
	MxS32 y = m_location.m_y;

	MxRect32 rect(x, y, width + x, height + y);
	MVideoManager()->InvalidateRect(rect);

	if (m_flags & Flag_Bit2) {
		undefined4 unk = 0;
		m_unk0x58 = MxOmni::GetInstance()->GetVideoManager()->GetDisplaySurface()->VTable0x44(
			m_bitmap,
			&unk,
			(m_flags & Flag_Bit4) / 8,
			m_action->GetFlags() & MxDSAction::Flag_Bit4
		);

		delete m_alpha;
		m_alpha = new AlphaMask(*m_bitmap);

		delete m_bitmap;
		m_bitmap = NULL;

		if (m_unk0x58 && unk)
			m_flags |= Flag_Bit3;
		else
			m_flags &= ~Flag_Bit3;
	}
}

// FUNCTION: LEGO1 0x100b9f30
void MxStillPresenter::RealizePalette()
{
	MxPalette* palette = m_bitmap->CreatePalette();
	MVideoManager()->RealizePalette(palette);
	delete palette;
}

// FUNCTION: LEGO1 0x100b9f60
void MxStillPresenter::StartingTickle()
{
	MxVideoPresenter::StartingTickle();

	if (m_currentTickleState == TickleState_Streaming && ((MxDSMediaAction*) m_action)->GetPaletteManagement())
		RealizePalette();
}

// FUNCTION: LEGO1 0x100b9f90
void MxStillPresenter::StreamingTickle()
{
	MxStreamChunk* chunk = FUN_100b5650();

	if (chunk && m_action->GetElapsedTime() >= chunk->GetTime()) {
		m_chunkTime = chunk->GetTime();
		NextFrame();
		m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
		m_currentTickleState = TickleState_Repeating;

		if (m_action->GetDuration() == -1 && m_compositePresenter)
			m_compositePresenter->VTable0x60(this);
	}
}

// FUNCTION: LEGO1 0x100b9ff0
void MxStillPresenter::RepeatingTickle()
{
	if (m_action->GetDuration() != -1) {
		if (m_action->GetElapsedTime() >= m_action->GetStartTime() + m_action->GetDuration()) {
			m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
			m_currentTickleState = TickleState_unk5;
		}
	}
}

// FUNCTION: LEGO1 0x100ba040
void MxStillPresenter::VTable0x88(MxS32 p_x, MxS32 p_y)
{
	MxS32 x = m_location.m_x;
	MxS32 y = m_location.m_y;
	m_location.m_x = p_x;
	m_location.m_y = p_y;

	if (IsEnabled()) {
		MxS32 height = GetHeight() - 1;
		MxS32 width = GetWidth() - 1;

		MxRect32 rect_a(x, y, width + x, height + y);
		MxRect32 rect_b(m_location.m_x, m_location.m_y, width + m_location.m_x, height + m_location.m_y);

		MVideoManager()->InvalidateRect(rect_a);
		MVideoManager()->VTable0x34(rect_a.GetLeft(), rect_a.GetTop(), rect_a.GetWidth(), rect_a.GetHeight());

		MVideoManager()->InvalidateRect(rect_b);
		MVideoManager()->VTable0x34(rect_b.GetLeft(), rect_b.GetTop(), rect_b.GetWidth(), rect_b.GetHeight());
	}
}

// FUNCTION: LEGO1 0x100ba140
void MxStillPresenter::Enable(MxBool p_enable)
{
	MxVideoPresenter::Enable(p_enable);

	if (MVideoManager() && (m_alpha || m_bitmap)) {
		MxS32 height = GetHeight();
		MxS32 width = GetWidth();
		MxS32 x = m_location.m_x;
		MxS32 y = m_location.m_y;

		MxRect32 rect(x, y, width + x, height + y);
		MVideoManager()->InvalidateRect(rect);
		MVideoManager()->VTable0x34(rect.GetLeft(), rect.GetTop(), rect.GetWidth(), rect.GetHeight());
	}
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
