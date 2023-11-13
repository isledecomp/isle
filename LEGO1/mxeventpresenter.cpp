#include "mxeventpresenter.h"

#include "decomp.h"
#include "mxautolocker.h"
#include "mxeventmanager.h"
#include "mxomni.h"
#include "mxvariabletable.h"

DECOMP_SIZE_ASSERT(MxEventPresenter, 0x54);

// OFFSET: LEGO1 0x100c2b70
MxEventPresenter::MxEventPresenter()
{
	Init();
}

// OFFSET: LEGO1 0x100c2d40
MxEventPresenter::~MxEventPresenter()
{
	Destroy();
}

// OFFSET: LEGO1 0x100c2da0
void MxEventPresenter::Init()
{
	m_data = NULL;
}

// OFFSET: LEGO1 0x100c2db0
MxResult MxEventPresenter::AddToManager()
{
	MxResult ret = FAILURE;

	if (EventManager()) {
		ret = SUCCESS;
		EventManager()->AddPresenter(*this);
	}

	return ret;
}

// OFFSET: LEGO1 0x100c2de0
void MxEventPresenter::Destroy()
{
	if (EventManager())
		EventManager()->RemovePresenter(*this);

	m_criticalSection.Enter();

	if (m_data)
		delete[] m_data;

	Init();

	m_criticalSection.Leave();
}

// OFFSET: LEGO1 0x100c2e30
void MxEventPresenter::CopyData(MxStreamChunk* p_chunk)
{
	m_data = new MxU8[p_chunk->GetLength()];
	memcpy(m_data, p_chunk->GetData(), p_chunk->GetLength());
}

// OFFSET: LEGO1 0x100c2e70
void MxEventPresenter::ReadyTickle()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk) {
		CopyData(chunk);
		m_subscriber->FUN_100b8390(chunk);
		ParseExtra();
		m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
		m_currentTickleState = TickleState_Starting;
	}
}

// OFFSET: LEGO1 0x100c2eb0
void MxEventPresenter::StartingTickle()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk && m_action->GetElapsedTime() >= chunk->GetTime()) {
		m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
		m_currentTickleState = TickleState_Streaming;
	}
}

// OFFSET: LEGO1 0x100c2ef0
undefined4 MxEventPresenter::PutData()
{
	MxAutoLocker lock(&m_criticalSection);

	if (IsEnabled()) {
		if (m_currentTickleState >= TickleState_Streaming &&
			(m_currentTickleState <= TickleState_Repeating || m_currentTickleState == TickleState_Done)) {
			if (m_currentChunk && m_currentChunk->GetLength()) {
				if (m_data[12] == 2) {
					const char* data = (const char*) m_currentChunk->GetData();
					MxVariableTable* variableTable = VariableTable();

					const char* key = data;
					const char* value = &data[strlen(data) + 1];
					strlen(value);
					variableTable->SetVariable(key, value);
				}

				if (m_currentTickleState == TickleState_Streaming)
					m_subscriber->FUN_100b8390(m_currentChunk);
				m_currentChunk = NULL;
			}
		}
	}

	return 0;
}
