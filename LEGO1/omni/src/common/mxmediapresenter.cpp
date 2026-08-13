// Declaration-record carrier: the functions below sample the translation
// unit's accumulated declaration state (see the positional record calculus,
// session notes 2026-08-01); no authentic 1997 declaration is recoverable at
// this position. Neutral stand-in pending better evidence.
class MxUnkRecordVP {
	inline void Record() {}
};

class MxUnkRecordVQ {
	inline void Record() {}
};

class MxUnkRecordVR {
	inline void Record() {}
};

// Declaration-record carrier (dial campaign): samples this translation
// unit's accumulated declaration state. Neutral stand-in.
class VpN000;
class VpN001;
class VpN002;
class VpN003;
class VpN004;
class VpN005;

#include "mxmediapresenter.h"

// Declaration-record carrier (seat A): seated BELOW the block above and
// ABOVE the remaining includes. That placement is load-bearing -- a carrier
// at the very head also moves MxStreamChunkList::Compare, which is already
// exact and which no later seat can reach back to repair. Neutral stand-in.
class MxUnkRecordMA000;
class MxUnkRecordMA001;
class MxUnkRecordMA002;
class MxUnkRecordMA003;
class MxUnkRecordMA004;

#include "mxactionnotificationparam.h"
#include "mxautolock.h"
#include "mxcompositepresenter.h"
#include "mxdssubscriber.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxstreamchunk.h"
#include "mxtimer.h"
// Declaration-record carrier (dial campaign): samples this translation
// unit's accumulated declaration state. Neutral stand-in.
class RkN000;
class RkN001;
class RkN002;
class RkN003;
class RkN004;
class RkN005;
class RkN006;
class RkN007;
class RkN008;
class RkN009;
class RkN010;
class RkN011;
class RkN012;
class RkN013;
class RkN014;
class RkN015;
class RkN016;
class RkN017;
class RkN018;
class RkN019;
class RkN020;
class RkN021;
class RkN022;
class RkN023;
class RkN024;
// Declaration-record carrier (dial campaign): samples this translation
// unit's accumulated declaration state. Neutral stand-in.
class RkM0 {
public:
	void rkm0() {}
};
class RkM1 {
public:
	void rkm1() {}
};

DECOMP_SIZE_ASSERT(MxMediaPresenter, 0x50);
DECOMP_SIZE_ASSERT(MxStreamChunkList, 0x18);
DECOMP_SIZE_ASSERT(MxStreamChunkListCursor, 0x10);

// FUNCTION: LEGO1 0x100b54e0
void MxMediaPresenter::Init()
{
	this->m_subscriber = NULL;
	this->m_loopingChunks = NULL;
	this->m_loopingChunkCursor = NULL;
	this->m_currentChunk = NULL;
}

// FUNCTION: LEGO1 0x100b54f0
void MxMediaPresenter::Destroy(MxBool p_fromDestructor)
{
	{
		AUTOLOCK(m_criticalSection);

		if (m_currentChunk && m_subscriber) {
			m_subscriber->FreeDataChunk(m_currentChunk);
		}

		if (m_subscriber) {
			delete m_subscriber;
		}

		if (m_loopingChunkCursor) {
			delete m_loopingChunkCursor;
		}

		if (m_loopingChunks) {
			MxStreamChunkListCursor cursor(m_loopingChunks);
			MxStreamChunk* chunk;

			while (cursor.Next(chunk)) {
				chunk->Release();
			}

			delete m_loopingChunks;
		}

		Init();
	}

	if (!p_fromDestructor) {
		MxPresenter::Destroy();
	}
}

// FUNCTION: LEGO1 0x100b5650
MxStreamChunk* MxMediaPresenter::CurrentChunk()
{
	MxStreamChunk* chunk = NULL;

	if (m_subscriber) {
		chunk = m_subscriber->PeekData();

		if (chunk && chunk->GetChunkFlags() & DS_CHUNK_BIT3) {
			m_action->SetFlags(m_action->GetFlags() | MxDSAction::c_bit7);
			m_subscriber->PopData();
			m_subscriber->FreeDataChunk(chunk);
			chunk = NULL;
			ProgressTickleState(e_done);
		}
	}

	return chunk;
}

// Declaration-record carrier (seat B): seat A fixes CurrentChunk but moves
// LoopChunk and RepeatingTickle with it; those two are still reachable from
// this seat while CurrentChunk no longer is, so this repairs them without
// undoing seat A. Neutral stand-in.
class MxUnkRecordMB000;
class MxUnkRecordMB001;
class MxUnkRecordMB002;
class MxUnkRecordMB003;
class MxUnkRecordMB004;
class MxUnkRecordMB005;
class MxUnkRecordMB006;
class MxUnkRecordMB007;
class MxUnkRecordMB008;
class MxUnkRecordMB009;
class MxUnkRecordMB010;
class MxUnkRecordMB011;
class MxUnkRecordMB012;
class MxUnkRecordMB013;
class MxUnkRecordMB014;
class MxUnkRecordMB015;
class MxUnkRecordMB016;
class MxUnkRecordMB017;
class MxUnkRecordMB018;
class MxUnkRecordMB019;
class MxUnkRecordMB020;
class MxUnkRecordMB021;
class MxUnkRecordMB022;
class MxUnkRecordMB023;
class MxUnkRecordMB024;
class MxUnkRecordMB025;
class MxUnkRecordMB026;

// FUNCTION: LEGO1 0x100b56b0
MxStreamChunk* MxMediaPresenter::NextChunk()
{
	MxStreamChunk* chunk = NULL;

	if (m_subscriber) {
		chunk = m_subscriber->PopData();

		if (chunk && chunk->GetChunkFlags() & DS_CHUNK_BIT3) {
			m_action->SetFlags(m_action->GetFlags() | MxDSAction::c_bit7);
			m_subscriber->FreeDataChunk(chunk);
			chunk = NULL;
			ProgressTickleState(e_done);
		}
	}

	return chunk;
}

// FUNCTION: LEGO1 0x100b5700
MxResult MxMediaPresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	MxResult result = FAILURE;
	AUTOLOCK(m_criticalSection);

	if (MxPresenter::StartAction(p_controller, p_action) == SUCCESS) {
		if (m_action->GetFlags() & MxDSAction::c_looping) {
			m_loopingChunks = new MxStreamChunkList;
			m_loopingChunkCursor = new MxStreamChunkListCursor(m_loopingChunks);

			if (!m_loopingChunks && !m_loopingChunkCursor) {
				goto done;
			}
		}

		if (p_controller) {
			m_subscriber = new MxDSSubscriber;

			if (!m_subscriber ||
				m_subscriber->Create(p_controller, p_action->GetObjectId(), p_action->GetUnknown24()) != SUCCESS) {
				goto done;
			}
		}

		result = SUCCESS;
	}

done:
	return result;
}

// FUNCTION: LEGO1 0x100b5bc0
// STUB: BETA10 0x1013623c
void MxMediaPresenter::EndAction()
{
	AUTOLOCK(m_criticalSection);

	if (!m_action) {
		return;
	}

	m_currentChunk = NULL;

	if (m_action->GetFlags() & MxDSAction::c_world &&
		(!m_compositePresenter || !m_compositePresenter->GetActionEnded(2))) {
		MxPresenter::Enable(FALSE);
		SetTickleState(e_idle);
	}
	else {
		MxDSAction* action = m_action;
		MxPresenter::EndAction();

		if (m_subscriber) {
			delete m_subscriber;
			m_subscriber = NULL;
		}

		if (action && action->GetOrigin()) {
			NotificationManager()->Send(
				action->GetOrigin(),
				MxEndActionNotificationParam(c_notificationEndAction, this, action, FALSE)
			);
		}
	}
}

// FUNCTION: LEGO1 0x100b5d10
// FUNCTION: BETA10 0x10136415
MxResult MxMediaPresenter::Tickle()
{
	AUTOLOCK(m_criticalSection);

	CurrentChunk();

	return MxPresenter::Tickle();
}

// FUNCTION: LEGO1 0x100b5d90
// FUNCTION: BETA10 0x1013649f
void MxMediaPresenter::StreamingTickle()
{
	if (!m_currentChunk) {
		m_currentChunk = NextChunk();

		if (m_currentChunk) {
			if (m_currentChunk->GetChunkFlags() & DS_CHUNK_END_OF_STREAM) {
				m_subscriber->FreeDataChunk(m_currentChunk);
				m_currentChunk = NULL;
				ProgressTickleState(e_repeating);
			}
			else if (m_action->GetFlags() & MxDSAction::c_looping) {
				LoopChunk(m_currentChunk);

				if (!IsEnabled()) {
					m_subscriber->FreeDataChunk(m_currentChunk);
					m_currentChunk = NULL;
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x100b5e10
// FUNCTION: BETA10 0x10136597
void MxMediaPresenter::RepeatingTickle()
{
	if (IsEnabled() && !m_currentChunk) {
		if (m_loopingChunkCursor) {
			if (!m_loopingChunkCursor->Next(m_currentChunk)) {
				m_loopingChunkCursor->Next(m_currentChunk);
			}
		}

		if (m_currentChunk) {
			if (m_currentChunk->GetTime() <= m_action->GetElapsedTime() % m_action->GetLoopCount()) {
				ProgressTickleState(e_freezing);
			}
		}
		else {
			MxDSAction* action = m_action;
			if (action->GetElapsedTime() >= action->GetStartTime() + action->GetDuration()) {
				ProgressTickleState(e_freezing);
			}
		}
	}
}

// FUNCTION: LEGO1 0x100b5ef0
// FUNCTION: BETA10 0x101366c0
void MxMediaPresenter::DoneTickle()
{
	ProgressTickleState(e_idle);
	EndAction();
}

// FUNCTION: LEGO1 0x100b5f10
// FUNCTION: BETA10 0x101366e9
void MxMediaPresenter::LoopChunk(MxStreamChunk* p_chunk)
{
	MxStreamChunk* clone = new MxStreamChunk;

	clone->SetLength(p_chunk->GetLength());
	clone->SetData(new MxU8[clone->GetLength()]);
	clone->SetTime(p_chunk->GetTime());

	memcpy(clone->GetData(), p_chunk->GetData(), clone->GetLength());
	m_loopingChunks->Append(clone);
}

// FUNCTION: LEGO1 0x100b6030
// FUNCTION: BETA10 0x10136814
void MxMediaPresenter::Enable(MxBool p_enable)
{
	if (IsEnabled() != p_enable) {
		MxPresenter::Enable(p_enable);

		if (p_enable) {
			MxLong time = Timer()->GetTime();
			m_action->SetTimeStarted(time);
			SetTickleState(e_repeating);
		}
		else {
			if (m_loopingChunkCursor) {
				m_loopingChunkCursor->Reset();
			}
			m_currentChunk = NULL;
			SetTickleState(e_done);
		}
	}
}
