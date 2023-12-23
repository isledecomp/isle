#include "mxdssubscriber.h"

#include "mxstreamcontroller.h"

DECOMP_SIZE_ASSERT(MxDSSubscriber, 0x4c);

// FUNCTION: LEGO1 0x100b7bb0
MxDSSubscriber::MxDSSubscriber()
{
	m_unk0x48 = -1;
	m_objectId = -1;
	m_unk0x20 = NULL;
	m_unk0x3c = NULL;
}

// FUNCTION: LEGO1 0x100b7e00
MxDSSubscriber::~MxDSSubscriber()
{
	if (m_controller)
		m_controller->FUN_100c1620(this);

	FUN_100b8030();

	if (m_unk0x20)
		delete m_unk0x20;
	m_unk0x20 = NULL;

	if (m_unk0x3c)
		delete m_unk0x3c;
	m_unk0x3c = NULL;
}

// FUNCTION: LEGO1 0x100b7ed0
MxResult MxDSSubscriber::Create(MxStreamController* p_controller, MxU32 p_objectId, MxS16 p_unk0x48)
{
	m_objectId = p_objectId;
	m_unk0x48 = p_unk0x48;

	if (!p_controller)
		return FAILURE;
	m_controller = p_controller;

	m_unk0x20 = new MxStreamChunkListCursor(&m_unk0x08);
	if (!m_unk0x20)
		return FAILURE;

	m_unk0x3c = new MxStreamChunkListCursor(&m_unk0x24);
	if (!m_unk0x3c)
		return FAILURE;

	m_controller->FUN_100c15d0(this);
	return SUCCESS;
}

// STUB: LEGO1 0x100b8030
void MxDSSubscriber::FUN_100b8030()
{
	// TODO
}

// STUB: LEGO1 0x100b8250
MxStreamChunk* MxDSSubscriber::FUN_100b8250()
{
	// TODO
	return NULL;
}

// STUB: LEGO1 0x100b8360
MxStreamChunk* MxDSSubscriber::FUN_100b8360()
{
	// TODO
	return NULL;
}

// STUB: LEGO1 0x100b8390
void MxDSSubscriber::FUN_100b8390(MxStreamChunk*)
{
	// TODO
}
