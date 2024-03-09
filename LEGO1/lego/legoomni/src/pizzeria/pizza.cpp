#include "pizza.h"

#include "mxmisc.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(Pizza, 0x9c);

// FUNCTION: LEGO1 0x10037ef0
Pizza::Pizza()
{
	this->m_unk0x7c = 0;
	this->m_unk0x80 = 0;
	this->m_unk0x84 = 0;
	this->m_unk0x88 = 0;
	this->m_unk0x8c = -1;
	this->m_unk0x98 = 0;
	this->m_unk0x90 = 0x80000000;
}

// FUNCTION: LEGO1 0x10038100
Pizza::~Pizza()
{
	TickleManager()->UnregisterClient(this);
}

// STUB: LEGO1 0x10038170
MxResult Pizza::Create(MxDSAction& p_dsAction)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x100388a0
MxResult Pizza::Tickle()
{
	// TODO
	return SUCCESS;
}
