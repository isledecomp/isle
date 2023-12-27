#include "legoworldpresenter.h"

#include "legoentity.h"
#include "legoomni.h"

// GLOBAL: LEGO1 0x100f75d4
undefined4 g_legoWorldPresenterQuality = 1;

// FUNCTION: LEGO1 0x100665b0
void LegoWorldPresenter::configureLegoWorldPresenter(MxS32 p_legoWorldPresenterQuality)
{
	g_legoWorldPresenterQuality = p_legoWorldPresenterQuality;
}

// FUNCTION: LEGO1 0x100665c0
LegoWorldPresenter::LegoWorldPresenter()
{
	m_unk0x50 = 50000;
}

// STUB: LEGO1 0x10066770
LegoWorldPresenter::~LegoWorldPresenter()
{
	// TODO
}

// STUB: LEGO1 0x10066870
MxResult LegoWorldPresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	return FAILURE;
}

// FUNCTION: LEGO1 0x10066a50
void LegoWorldPresenter::ReadyTickle()
{
	m_objectBackend = (LegoEntity*) MxPresenter::CreateEntityBackend("LegoWorld");
	if (m_objectBackend) {
		m_objectBackend->Create(*m_action);
		Lego()->AddWorld((LegoWorld*) m_objectBackend);
		SetBackendLocation(m_action->GetLocation(), m_action->GetDirection(), m_action->GetUp());
	}

	ParseExtra();
	m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
	m_currentTickleState = TickleState_Starting;
}

// STUB: LEGO1 0x10066ac0
void LegoWorldPresenter::StartingTickle()
{
}

// STUB: LEGO1 0x10067a70
void LegoWorldPresenter::VTable0x60(MxPresenter* p_presenter)
{
}

// STUB: LEGO1 0x10067b00
void LegoWorldPresenter::ParseExtra()
{
}
