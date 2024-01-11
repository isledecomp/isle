#include "legoactioncontrolpresenter.h"

#include "define.h"
#include "extra.h"
#include "legoomni.h"
#include "legoutil.h"
#include "mxcompositepresenter.h"
#include "mxmediapresenter.h"
#include "mxomni.h"
#include "mxstreamchunk.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(LegoActionControlPresenter, 0x68)

// FUNCTION: LEGO1 0x10043ce0
void LegoActionControlPresenter::ReadyTickle()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk) {
		ParseExtra();
		ProgressTickleState(TickleState_Starting);

		m_subscriber->DestroyChunk(chunk);
		if (m_compositePresenter) {
			if (m_action->GetDuration() == -1 || m_action->GetFlags() & 1) {
				m_compositePresenter->VTable0x60(this);
			}
		}
	}
}

// FUNCTION: LEGO1 0x10043d40
void LegoActionControlPresenter::RepeatingTickle()
{
	if (IsEnabled()) {
		if (m_unk0x50 == 0) {
			ParseExtra();
		}

#ifdef COMPAT_MODE
		{
			MxAtomId atom(m_unk0x54.GetData(), LookupMode_LowerCase2);
			InvokeAction(m_unk0x50, atom, m_unk0x64, NULL);
		}
#else
		InvokeAction(m_unk0x50, MxAtomId(m_unk0x54.GetData(), LookupMode_LowerCase2), m_unk0x64, NULL);
#endif
		ProgressTickleState(TickleState_Done);
	}
}

// FUNCTION: LEGO1 0x10043df0
MxResult LegoActionControlPresenter::AddToManager()
{
	MxResult result = FAILURE;

	if (TickleManager()) {
		result = SUCCESS;
		TickleManager()->RegisterClient(this, 100);
	}

	return result;
}

// FUNCTION: LEGO1 0x10043e20
void LegoActionControlPresenter::Destroy(MxBool p_fromDestructor)
{
	if (TickleManager()) {
		TickleManager()->UnregisterClient(this);
	}

	if (!p_fromDestructor) {
		MxMediaPresenter::Destroy(FALSE);
	}
}

// FUNCTION: LEGO1 0x10043e50
void LegoActionControlPresenter::ParseExtra()
{
	MxU32 len = m_action->GetExtraLength();

	if (len == 0)
		return;

	len &= MAXWORD;

	char buf[1024];
	memcpy(buf, m_action->GetExtraData(), len);
	buf[len] = '\0';

	char output[1024];
	if (KeyValueStringParse(output, g_strACTION, buf)) {
		m_unk0x50 = MatchActionString(strtok(output, g_parseExtraTokens));
		if (m_unk0x50 != ExtraActionType_exit) {
			MakeSourceName(buf, strtok(NULL, g_parseExtraTokens));
			m_unk0x54 = buf;
			m_unk0x54.ToLowerCase();
			if (m_unk0x50 != ExtraActionType_run) {
				m_unk0x64 = atoi(strtok(NULL, g_parseExtraTokens));
			}
		}
	}
}
