#include "legopathpresenter.h"

#include "legovideomanager.h"
#include "misc.h"
#include "mxautolock.h"
#include "mxutilities.h"

DECOMP_SIZE_ASSERT(LegoPathPresenter, 0x54)

// STRING: LEGO1 0x10101ef0
// GLOBAL: LEGO1 0x101020c4
const char* g_triggersSource = "TRIGGERS_SOURCE";

// FUNCTION: LEGO1 0x100448d0
LegoPathPresenter::LegoPathPresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x10044ab0
void LegoPathPresenter::Init()
{
}

// FUNCTION: LEGO1 0x10044ac0
LegoPathPresenter::~LegoPathPresenter()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x10044b40
MxResult LegoPathPresenter::AddToManager()
{
	MxResult status = FAILURE;

	if (VideoManager()) {
		VideoManager()->RegisterPresenter(*this);
		status = SUCCESS;
	}

	return status;
}

// FUNCTION: LEGO1 0x10044b70
void LegoPathPresenter::Destroy(MxBool p_fromDestructor)
{
	if (VideoManager()) {
		VideoManager()->UnregisterPresenter(*this);
	}

	{
		AUTOLOCK(m_criticalSection);
		Init();
	}

	if (!p_fromDestructor) {
		MxMediaPresenter::Destroy(FALSE);
	}
}

// FUNCTION: LEGO1 0x10044c10
void LegoPathPresenter::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x10044c20
void LegoPathPresenter::ReadyTickle()
{
	LegoWorld* currentWorld = CurrentWorld();

	if (currentWorld) {
		MxStreamChunk* chunk = m_subscriber->PopData();

		if (chunk) {
			LegoPathController* controller = new LegoPathController();

			if (controller == NULL) {
				EndAction();
			}
			else {
				ParseExtra();

				controller->VTable0x14(chunk->GetData(), m_action->GetLocation(), m_trigger);
				currentWorld->AddPath(controller);

				m_subscriber->FreeDataChunk(chunk);
				ProgressTickleState(MxPresenter::e_starting);
			}
		}
	}
}

// FUNCTION: LEGO1 0x10044d00
void LegoPathPresenter::StreamingTickle()
{
	MxStreamChunk* chunk = m_subscriber->PopData();

	if (chunk) {
		if (chunk->GetFlags() & MxStreamChunk::c_end) {
			ProgressTickleState(e_repeating);
		}

		m_subscriber->FreeDataChunk(chunk);
	}
}

// FUNCTION: LEGO1 0x10044d40
void LegoPathPresenter::RepeatingTickle()
{
	if (this->m_action->GetDuration() == -1) {
		return;
	}

	EndAction();
}

// FUNCTION: LEGO1 0x10044d60
void LegoPathPresenter::ParseExtra()
{
	MxU16 extraLength;
	char* extraData;
	m_action->GetExtra(extraLength, extraData);

	if (extraLength & MAXWORD) {
		char extraCopy[256], output[256];
		memcpy(extraCopy, extraData, extraLength & MAXWORD);
		extraCopy[extraLength & MAXWORD] = '\0';

		strupr(extraCopy);

		if (KeyValueStringParse(output, g_triggersSource, extraCopy) != FALSE) {
			m_trigger = MxAtomId(output, e_lowerCase2);
		}
	}
}
