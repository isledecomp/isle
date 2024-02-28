#include "legolocomotionanimpresenter.h"

#include "legoomni.h"
#include "legoworld.h"

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
	m_unk0xc4 = 0;
	m_unk0xcc = -1;
	m_unk0xd0 = -1;
	m_unk0xc8 = 0;
	m_unk0xd4 = 0;
}

// FUNCTION: LEGO1 0x1006d0e0
void LegoLocomotionAnimPresenter::Destroy(MxBool p_fromDestructor)
{
	m_criticalSection.Enter();

	if (m_unk0xc4) {
		delete[] m_unk0xc4;
	}

	if (m_unk0xc8) {
		delete m_unk0xc8;
	}

	m_unk0x68 = NULL;
	Init();

	m_criticalSection.Leave();

	if (!p_fromDestructor) {
		LegoAnimPresenter::Destroy();
	}
}

// FUNCTION: LEGO1 0x1006d140
MxResult LegoLocomotionAnimPresenter::CreateAnim(MxStreamChunk* p_chunk)
{
	MxResult result = LegoAnimPresenter::CreateAnim(p_chunk);
	return result == SUCCESS ? SUCCESS : result;
}

// STUB: LEGO1 0x1006d160
MxResult LegoLocomotionAnimPresenter::AddToManager()
{
	return MxVideoPresenter::AddToManager();
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
	LegoAnimPresenter::ReadyTickle();

	if (m_currentWorld != NULL && m_currentTickleState == e_starting) {
		m_currentWorld->Add(this);
		if (m_compositePresenter != NULL) {
			SendToCompositePresenter(Lego());
		}

		m_unk0xd4++;
	}
}

// STUB: LEGO1 0x1006d610
void LegoLocomotionAnimPresenter::StartingTickle()
{
	// TODO
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
