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
const char* g_strBmpIsmap = "BMP_ISMAP";

// FUNCTION: LEGO1 0x100435b0
void MxStillPresenter::Destroy()
{
	Destroy(FALSE);
}

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

	MxRect32 rect(m_location, MxSize32(GetWidth() - 1, GetHeight() - 1));
	MVideoManager()->InvalidateRect(rect);

	if (m_flags & Flag_Bit2) {
		undefined4 und = 0;
		m_unk0x58 = MxOmni::GetInstance()->GetVideoManager()->GetDisplaySurface()->VTable0x44(
			m_bitmap,
			&und,
			(m_flags & Flag_Bit4) / 8,
			m_action->GetFlags() & MxDSAction::Flag_Bit4
		);

		delete m_alpha;
		m_alpha = new AlphaMask(*m_bitmap);

		delete m_bitmap;
		m_bitmap = NULL;

		if (m_unk0x58 && und)
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
	MxS32 x = m_location.GetX();
	MxS32 y = m_location.GetY();
	m_location.SetX(p_x);
	m_location.SetY(p_y);

	if (IsEnabled()) {
		// Most likely needs to work with MxSize32 and MxPoint32
		MxS32 height = GetHeight() - 1;
		MxS32 width = GetWidth() - 1;

		MxRect32 rectA(x, y, width + x, height + y);
		MxRect32 rectB(m_location.GetX(), m_location.GetY(), width + m_location.GetX(), height + m_location.GetY());

		MVideoManager()->InvalidateRect(rectA);
		MVideoManager()->VTable0x34(rectA.GetLeft(), rectA.GetTop(), rectA.GetWidth(), rectA.GetHeight());

		MVideoManager()->InvalidateRect(rectB);
		MVideoManager()->VTable0x34(rectB.GetLeft(), rectB.GetTop(), rectB.GetWidth(), rectB.GetHeight());
	}
}

// FUNCTION: LEGO1 0x100ba140
void MxStillPresenter::Enable(MxBool p_enable)
{
	MxVideoPresenter::Enable(p_enable);

	if (MVideoManager() && (m_alpha || m_bitmap)) {
		MxRect32 rect(m_location, MxSize32(GetWidth(), GetHeight()));
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

	if (KeyValueStringParse(output, g_strBmpIsmap, buf)) {
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
