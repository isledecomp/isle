#include "legoactorpresenter.h"

#include "legoentity.h"
#include "legoomni.h"

// FUNCTION: LEGO1 0x10076c30
void LegoActorPresenter::ReadyTickle()
{
	if (GetCurrentWorld()) {
		m_entity = (LegoEntity*) CreateEntity("LegoActor");
		if (m_entity) {
			SetEntityLocation(m_action->GetLocation(), m_action->GetDirection(), m_action->GetUp());
			m_entity->Create(*m_action);
		}
		ProgressTickleState(TickleState_Starting);
	}
}

// FUNCTION: LEGO1 0x10076c90
void LegoActorPresenter::StartingTickle()
{
	if (m_entity->GetROI()) {
		ProgressTickleState(TickleState_Streaming);
		ParseExtra();
	}
}

// FUNCTION: LEGO1 0x10076cc0
void LegoActorPresenter::ParseExtra()
{
	char buffer[512];
	char* extraData = m_action->GetExtraData();
	if (m_action->GetExtraLength()) {
		memcpy(buffer, extraData, m_action->GetExtraLength());
		buffer[m_action->GetExtraLength()] = 0;

		m_entity->ParseAction(buffer);
	}
}
