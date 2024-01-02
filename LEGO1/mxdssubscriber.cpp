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
		m_controller->RemoveSubscriber(this);

	DeleteChunks();

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

	m_controller->AddSubscriber(this);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100b8030
void MxDSSubscriber::DeleteChunks()
{
	if (m_controller) {
		MxStreamChunk* chunk = NULL;

		while (m_unk0x20->First(chunk)) {
			m_unk0x20->Detach();
			delete chunk;
		}

		while (m_unk0x3c->First(chunk)) {
			m_unk0x3c->Detach();
			delete chunk;
		}
	}
}

// FUNCTION: LEGO1 0x100b8150
MxResult MxDSSubscriber::AddChunk(MxStreamChunk* p_chunk, MxBool p_append)
{
	if (m_unk0x20) {
		if (p_append)
			m_unk0x08.Append(p_chunk);
		else
			m_unk0x08.Prepend(p_chunk);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100b8250
MxStreamChunk* MxDSSubscriber::FUN_100b8250()
{
	MxStreamChunk* chunk = NULL;

	if (m_unk0x20)
		m_unk0x20->First(chunk);

	if (chunk) {
		m_unk0x20->Detach();
		m_unk0x24.Append(chunk);
	}

	return chunk;
}

// FUNCTION: LEGO1 0x100b8360
MxStreamChunk* MxDSSubscriber::FUN_100b8360()
{
	MxStreamChunk* chunk = NULL;

	if (m_unk0x20)
		m_unk0x20->First(chunk);

	return chunk;
}

// FUNCTION: LEGO1 0x100b8390
void MxDSSubscriber::FUN_100b8390(MxStreamChunk* p_chunk)
{
	if (p_chunk) {
		if (m_unk0x3c->Find(p_chunk)) {
			m_unk0x3c->Detach();
			if (p_chunk)
				delete p_chunk;
		}
		else if (p_chunk->GetFlags() & MxDSChunk::Flag_Bit1 && p_chunk)
			delete p_chunk;
	}
}
