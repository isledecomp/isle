#include "legopathpresenter.h"

#include "define.h"
#include "legopathcontroller.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "mxautolock.h"
#include "mxdssubscriber.h"
#include "mxutilities.h"

DECOMP_SIZE_ASSERT(LegoPathPresenter, 0x54)

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
	LegoWorld* world = CurrentWorld();

	if (world) {
		MxStreamChunk* chunk = m_subscriber->PopData();

		if (chunk) {
			LegoPathController* controller = new LegoPathController();

			if (controller == NULL) {
				EndAction();
			}
			else {
				ParseExtra();

				controller->Create(chunk->GetData(), m_action->GetLocation(), m_trigger);
				world->AddPath(controller);

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
		if (chunk->GetChunkFlags() & DS_CHUNK_END_OF_STREAM) {
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

	if (extraLength) {
		char extraCopy[256], output[256];
		memcpy(extraCopy, extraData, extraLength);
		extraCopy[extraLength] = '\0';

		strupr(extraCopy);

		if (KeyValueStringParse(output, g_strTRIGGERS_SOURCE, extraCopy) != FALSE) {
			m_trigger = MxAtomId(output, e_lowerCase2);
		}
	}
}
