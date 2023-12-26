#include "legoentitypresenter.h"

#include "islepathactor.h"
#include "legoomni.h"
#include "legovideomanager.h"

DECOMP_SIZE_ASSERT(LegoEntityPresenter, 0x50);

// FUNCTION: LEGO1 0x10053440
LegoEntityPresenter::LegoEntityPresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x100535c0
void LegoEntityPresenter::Init()
{
	m_objectBackend = 0;
}

// FUNCTION: LEGO1 0x100535d0
LegoEntityPresenter::~LegoEntityPresenter()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x10053630
undefined4 LegoEntityPresenter::SetBackend(LegoEntity* p_backend)
{
	m_objectBackend = p_backend;
	return 0;
}

// FUNCTION: LEGO1 0x10053640
void LegoEntityPresenter::Destroy(MxBool p_fromDestructor)
{
	if (VideoManager()) {
		VideoManager()->RemovePresenter(*this);
	}

	Init();
}

// FUNCTION: LEGO1 0x10053670
void LegoEntityPresenter::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x10053680
MxResult LegoEntityPresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	MxResult result = MxCompositePresenter::StartAction(p_controller, p_action);

	if (VideoManager()) {
		VideoManager()->AddPresenter(*this);
	}

	return result;
}

// FUNCTION: LEGO1 0x100536c0
void LegoEntityPresenter::ReadyTickle()
{
	if (GetCurrentWorld()) {
		m_objectBackend = (LegoEntity*) MxPresenter::CreateEntityBackend("LegoEntity");
		if (m_objectBackend) {
			m_objectBackend->Create(*m_action);
			m_objectBackend->SetLocation(m_action->GetLocation(), m_action->GetDirection(), m_action->GetUp(), TRUE);
			ParseExtra();
		}
		m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
		m_currentTickleState = TickleState_Starting;
	}
}

// FUNCTION: LEGO1 0x10053720
void LegoEntityPresenter::RepeatingTickle()
{
	if (m_list.empty()) {
		EndAction();
	}
}

// FUNCTION: LEGO1 0x10053750
void LegoEntityPresenter::ParseExtra()
{
	char data[512];
	MxU16 len = m_action->GetExtraLength();
	if (len) {
		memcpy(data, m_action->GetExtraData(), len);
		data[len] = 0;

		len &= MAXWORD;
		m_objectBackend->ParseAction(data);
	}
}
