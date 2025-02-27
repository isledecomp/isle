#include "legolocomotionanimpresenter.h"

#include "anim/legoanim.h"
#include "legoanimactor.h"
#include "legomain.h"
#include "legoworld.h"
#include "misc.h"
#include "mxautolock.h"
#include "mxdssubscriber.h"
#include "mxmisc.h"
#include "mxvariabletable.h"

DECOMP_SIZE_ASSERT(LegoLocomotionAnimPresenter, 0xd8)

// FUNCTION: LEGO1 0x1006cdd0
LegoLocomotionAnimPresenter::LegoLocomotionAnimPresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x1006d050
LegoLocomotionAnimPresenter::~LegoLocomotionAnimPresenter()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x1006d0b0
void LegoLocomotionAnimPresenter::Init()
{
	m_unk0xc0 = 0;
	m_unk0xc4 = NULL;
	m_unk0xcc = -1;
	m_unk0xd0 = -1;
	m_roiMapList = NULL;
	m_unk0xd4 = 0;
}

// FUNCTION: LEGO1 0x1006d0e0
void LegoLocomotionAnimPresenter::Destroy(MxBool p_fromDestructor)
{
	m_criticalSection.Enter();

	if (m_unk0xc4) {
		delete[] m_unk0xc4;
	}

	if (m_roiMapList) {
		delete m_roiMapList;
	}

	m_roiMap = NULL;
	Init();

	m_criticalSection.Leave();

	if (!p_fromDestructor) {
		LegoLoopingAnimPresenter::Destroy();
	}
}

// FUNCTION: LEGO1 0x1006d140
MxResult LegoLocomotionAnimPresenter::CreateAnim(MxStreamChunk* p_chunk)
{
	MxResult result = LegoAnimPresenter::CreateAnim(p_chunk);
	return result == SUCCESS ? SUCCESS : result;
}

// FUNCTION: LEGO1 0x1006d160
// FUNCTION: BETA10 0x100528c7
MxResult LegoLocomotionAnimPresenter::AddToManager()
{
	m_roiMapList = new LegoROIMapList();

	if (m_roiMapList == NULL) {
		return FAILURE;
	}

	return LegoAnimPresenter::AddToManager();
}

// FUNCTION: LEGO1 0x1006d5b0
void LegoLocomotionAnimPresenter::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x1006d5c0
void LegoLocomotionAnimPresenter::PutFrame()
{
	// Empty
}

// FUNCTION: LEGO1 0x1006d5d0
void LegoLocomotionAnimPresenter::ReadyTickle()
{
	LegoLoopingAnimPresenter::ReadyTickle();

	if (m_currentWorld != NULL && m_currentTickleState == e_starting) {
		m_currentWorld->Add(this);
		if (m_compositePresenter != NULL) {
			SendToCompositePresenter(Lego());
		}

		m_unk0xd4++;
	}
}

// FUNCTION: LEGO1 0x1006d610
// FUNCTION: BETA10 0x10052a34
void LegoLocomotionAnimPresenter::StartingTickle()
{
	if (m_subscriber->PeekData()) {
		MxStreamChunk* chunk = m_subscriber->PopData();
		m_subscriber->FreeDataChunk(chunk);
	}

	if (m_roiMapList->GetNumElements() != 0) {
		ProgressTickleState(e_streaming);
	}
}

// FUNCTION: LEGO1 0x1006d660
void LegoLocomotionAnimPresenter::StreamingTickle()
{
	if (m_unk0xd4 == 0) {
		EndAction();
	}
}

// FUNCTION: LEGO1 0x1006d670
void LegoLocomotionAnimPresenter::EndAction()
{
	if (m_action) {
		MxVideoPresenter::EndAction();
	}
}

// FUNCTION: LEGO1 0x1006d680
// FUNCTION: BETA10 0x10052b3d
void LegoLocomotionAnimPresenter::FUN_1006d680(LegoAnimActor* p_actor, MxFloat p_value)
{
	AUTOLOCK(m_criticalSection);

	MxVariableTable* variableTable = VariableTable();

	const char* key = ((LegoAnimNodeData*) m_anim->GetRoot()->GetData())->GetName();
	variableTable->SetVariable(key, p_actor->GetROI()->GetName());

	FUN_100695c0();
	FUN_10069b10();

	if (m_roiMap != NULL) {
		m_roiMapList->Append(m_roiMap);
		p_actor->FUN_1001c450(m_anim, p_value, m_roiMap, m_roiMapSize);
		m_roiMap = NULL;
	}

	variableTable->SetVariable(key, "");

	if (m_unk0x70 != NULL) {
		delete m_unk0x70;
		m_unk0x70 = NULL;
	}
}
