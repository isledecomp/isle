#include "legoactioncontrolpresenter.h"

#include "define.h"
#include "extra.h"
#include "legomain.h"
#include "legoutils.h"
#include "mxcompositepresenter.h"
#include "mxdssubscriber.h"
#include "mxmediapresenter.h"
#include "mxmisc.h"
#include "mxstreamchunk.h"
#include "mxticklemanager.h"
#include "mxutilities.h"

DECOMP_SIZE_ASSERT(LegoActionControlPresenter, 0x68)

// FUNCTION: LEGO1 0x10043ce0
void LegoActionControlPresenter::ReadyTickle()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk) {
		ParseExtra();
		ProgressTickleState(e_starting);

		m_subscriber->FreeDataChunk(chunk);
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

		InvokeAction(m_unk0x50, MxAtomId(m_unk0x54.GetData(), e_lowerCase2), m_unk0x64, NULL);
		ProgressTickleState(e_done);
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
	MxU16 extraLength;
	char* extraData;
	m_action->GetExtra(extraLength, extraData);

	if (extraLength) {
		char extraCopy[1024];
		memcpy(extraCopy, extraData, extraLength);
		extraCopy[extraLength] = '\0';

		char output[1024];
		if (KeyValueStringParse(output, g_strACTION, extraCopy)) {
			m_unk0x50 = MatchActionString(strtok(output, g_parseExtraTokens));

			if (m_unk0x50 != Extra::ActionType::e_exit) {
				MakeSourceName(extraCopy, strtok(NULL, g_parseExtraTokens));

				m_unk0x54 = extraCopy;
				m_unk0x54.ToLowerCase();
				if (m_unk0x50 != Extra::ActionType::e_run) {
					m_unk0x64 = atoi(strtok(NULL, g_parseExtraTokens));
				}
			}
		}
	}
}
