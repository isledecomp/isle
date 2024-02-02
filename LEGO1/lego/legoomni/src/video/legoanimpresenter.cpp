#include "legoanimpresenter.h"

#include "legoomni.h"
#include "legoworld.h"
#include "mxcompositepresenter.h"
#include "mxdsanim.h"
#include "mxstreamchunk.h"
#include "mxvideomanager.h"

DECOMP_SIZE_ASSERT(LegoAnimPresenter, 0xc0)
DECOMP_SIZE_ASSERT(LegoAnimClass, 0x18)

// FUNCTION: LEGO1 0x10068420
LegoAnimPresenter::LegoAnimPresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x10068670
LegoAnimPresenter::~LegoAnimPresenter()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x100686f0
void LegoAnimPresenter::Init()
{
	m_unk0x64 = NULL;
	m_unk0x68 = 0;
	m_unk0x6c = 0;
	m_unk0x74 = 0;
	m_unk0x70 = 0;
	m_unk0x78 = 0;
	m_unk0x7c = 0;
	m_unk0xa8.Clear();
	m_unk0xa4 = 0;
	m_currentWorld = NULL;
	m_unk0x95 = 0;
	m_unk0x88 = -1;
	m_unk0x98 = 0;
	m_animAtom.Clear();
	m_unk0x9c = 0;
	m_unk0x8c = 0;
	m_unk0x90 = 0;
	m_unk0x94 = 0;
	m_unk0x96 = 1;
	m_unk0xa0 = 0;
}

// STUB: LEGO1 0x10068770
void LegoAnimPresenter::Destroy(MxBool p_fromDestructor)
{
	// TODO
	MxVideoPresenter::Destroy(p_fromDestructor);
}

// FUNCTION: LEGO1 0x10068fb0
MxResult LegoAnimPresenter::VTable0x88(MxStreamChunk* p_chunk)
{
	MxResult result = FAILURE;
	LegoMemory stream((char*) p_chunk->GetData());

	MxS32 magicSig;
	MxS32 val2 = 0;
	MxS32 val3;

	if (stream.Read(&magicSig, sizeof(MxS32)) == SUCCESS && magicSig == 0x11) {
		if (stream.Read(&m_unk0xa4, sizeof(MxU32)) == SUCCESS) {
			if (stream.Read(&m_unk0xa8[0], sizeof(float)) == SUCCESS) {
				if (stream.Read(&m_unk0xa8[1], sizeof(float)) == SUCCESS) {
					if (stream.Read(&m_unk0xa8[2], sizeof(float)) == SUCCESS) {
						if (stream.Read(&val2, sizeof(MxS32)) == SUCCESS) {
							if (stream.Read(&val3, sizeof(MxS32)) == SUCCESS) {
								m_unk0x64 = new LegoAnimClass();
								if (m_unk0x64) {
									if (m_unk0x64->VTable0x10(&stream, val2) == SUCCESS) {
										result = SUCCESS;
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if (result != SUCCESS) {
		delete m_unk0x64;
		Init();
	}

	return result;
}

// STUB: LEGO1 0x1006ad30
void LegoAnimPresenter::PutFrame()
{
	// TODO
}

// FUNCTION: LEGO1 0x1006b550
void LegoAnimPresenter::ReadyTickle()
{
	m_currentWorld = CurrentWorld();

	if (m_currentWorld) {
		MxStreamChunk* chunk = m_subscriber->CurrentChunk();

		if (chunk && chunk->GetTime() + m_action->GetStartTime() <= m_action->GetElapsedTime()) {
			chunk = m_subscriber->NextChunk();
			MxResult result = VTable0x88(chunk);
			m_subscriber->DestroyChunk(chunk);

			if (result == SUCCESS) {
				ProgressTickleState(e_starting);
				ParseExtra();
			}
			else {
				EndAction();
			}
		}
	}
}

// STUB: LEGO1 0x1006b5e0
void LegoAnimPresenter::StartingTickle()
{
	// TODO
	ProgressTickleState(e_streaming);
	EndAction(); // Allow game to start
}

// FUNCTION: LEGO1 0x1006b840
void LegoAnimPresenter::StreamingTickle()
{
	if (m_subscriber->CurrentChunk()) {
		MxStreamChunk* chunk = m_subscriber->NextChunk();
		m_subscriber->DestroyChunk(chunk);
	}

	if (m_unk0x95) {
		ProgressTickleState(e_done);
		if (m_compositePresenter) {
			if (m_compositePresenter->IsA("LegoAnimMMPresenter")) {
				m_compositePresenter->VTable0x60(this);
			}
		}
	}
	else {
		if (m_action->GetElapsedTime() > m_unk0x64->GetUnknown0x8() + m_action->GetStartTime()) {
			m_unk0x95 = 1;
		}
	}
}

// STUB: LEGO1 0x1006b8c0
void LegoAnimPresenter::DoneTickle()
{
	// TODO
}

// FUNCTION: LEGO1 0x1006b8d0
MxResult LegoAnimPresenter::AddToManager()
{
	return MxVideoPresenter::AddToManager();
}

// FUNCTION: LEGO1 0x1006b8e0
void LegoAnimPresenter::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x1006b8f0
const char* LegoAnimPresenter::GetActionObjectName()
{
	return m_action->GetObjectName();
}

// STUB: LEGO1 0x1006bac0
void LegoAnimPresenter::ParseExtra()
{
	// TODO
}

// FUNCTION: LEGO1 0x1006c620
MxResult LegoAnimPresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	MxResult result = MxVideoPresenter::StartAction(p_controller, p_action);
	m_displayZ = 0;
	return result;
}

// STUB: LEGO1 0x1006c640
void LegoAnimPresenter::EndAction()
{
	// TODO
	MxVideoPresenter::EndAction();
}

// FUNCTION: LEGO1 0x100a0b30
LegoAnimClass::LegoAnimClass()
{
	m_unk0x08 = 0;
	m_unk0x0c = 0;
	m_unk0x10 = 0;
	m_unk0x14 = 0;
}

// STUB: LEGO1 0x100a0bc0
LegoAnimClass::~LegoAnimClass()
{
	// TODO
}

// STUB: LEGO1 0x100a0c70
MxResult LegoAnimClass::VTable0x10(LegoMemory* p_stream, MxS32)
{
	return SUCCESS;
}

// STUB: LEGO1 0x100a0e30
LegoResult LegoAnimClass::Write(LegoStorage* p_storage)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x100a1040
LegoTreeNodeData* LegoAnimClass::CreateData()
{
	// TODO
	return NULL;
}
