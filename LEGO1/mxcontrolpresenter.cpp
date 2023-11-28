#include "mxcontrolpresenter.h"

#include "legoomni.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(MxControlPresenter, 0x5c)

// FUNCTION: LEGO1 0x10043f50
MxControlPresenter::MxControlPresenter()
{
	this->m_unk4c = 0;
	this->m_unk4e = -1;
	this->m_unk50 = 0;
	this->m_unk52 = 0;
	this->m_unk58 = 0;
	this->m_unk54 = 0;
}

// FUNCTION: LEGO1 0x10044110
MxControlPresenter::~MxControlPresenter()
{
	if (this->m_unk58) {
		delete this->m_unk58;
	}
}

// FUNCTION: LEGO1 0x10044610
void MxControlPresenter::ReadyTickle()
{
	MxPresenter::ParseExtra();
	TickleManager()->UnregisterClient(this);

	m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
	m_currentTickleState = TickleState_Repeating;
}
