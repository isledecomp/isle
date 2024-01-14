#include "legoanimpresenter.h"

#include "legoomni.h"
#include "legostream.h"
#include "legoworld.h"
#include "mxdsanim.h"
#include "mxstreamchunk.h"

DECOMP_SIZE_ASSERT(LegoAnimPresenter, 0xc0);

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
	m_vec.Clear();
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
	return MxVideoPresenter::Destroy(p_fromDestructor);
}

// FUNCTION: LEGO1 0x1006b550
void LegoAnimPresenter::ReadyTickle()
{
	m_currentWorld = GetCurrentWorld();
	if (m_currentWorld) {
		MxStreamChunk* chunk = m_subscriber->CurrentChunk();
		if (chunk) {
			if (chunk->GetTime() + m_action->GetStartTime() <= m_action->GetElapsedTime()) {
				chunk = m_subscriber->NextChunk();
				MxU32 result = VTable0x88(chunk);
				m_subscriber->DestroyChunk(chunk);

				if (result == 0) {
					ProgressTickleState(TickleState_Starting);
					ParseExtra();
				}
				else {
					EndAction();
				}
			}
		}
	}
}

// STUB: LEGO1 0x1006c620
MxResult LegoAnimPresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	// TODO
	return MxVideoPresenter::StartAction(p_controller, p_action);
}

// STUB: LEGO1 0x1006b5e0
void LegoAnimPresenter::StartingTickle()
{
	// TODO
}

// STUB: LEGO1 0x1006b840
void LegoAnimPresenter::StreamingTickle()
{
	// TODO
}

// STUB: LEGO1 0x1006bac0
void LegoAnimPresenter::ParseExtra()
{
	// TODO
}

// FUNCTION: LEGO1 0x1006b8e0
void LegoAnimPresenter::Destroy()
{
	Destroy(FALSE);
}

// STUB: LEGO1 0x1006c640
void LegoAnimPresenter::EndAction()
{
	// TODO
}

// STUB: LEGO1 0x1006ad30
void LegoAnimPresenter::PutFrame()
{
	// TODO
}

// STUB: LEGO1 0x10068fb0
MxS32 LegoAnimPresenter::VTable0x88(MxStreamChunk* p_chunk)
{
	LegoMemoryStream stream((char*) p_chunk->GetData());
	MxS32 val = 0;
	MxS32 val2 = 0;
	MxS32 result = -1;

	if (stream.Read(&val, sizeof(MxS32)) == SUCCESS && val == 0x11) {
		if (stream.Read(&m_unk0xa4, sizeof(MxU32)) == SUCCESS) {
			if (stream.Read(m_vec.GetX(), sizeof(float)) == SUCCESS) {
				if (stream.Read(m_vec.GetY(), sizeof(float)) == SUCCESS) {
					if (stream.Read(m_vec.GetZ(), sizeof(float)) == SUCCESS) {
						if (stream.Read(&val2, sizeof(MxS32)) == SUCCESS) {

							MxS32 val3;
							if (stream.Read(&val3, sizeof(MxS32)) == SUCCESS) {
								m_unk0x64 = new LegoAnimClass();
								if (m_unk0x64) {
									if (m_unk0x64->VTable0x10() == SUCCESS) {
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

	if (result != 0) {
		delete m_unk0x64;
		Init();
	}

	return result;
}

// FUNCTION: LEGO1 0x10099dd0
LegoAnimClassBase::LegoAnimClassBase()
{
	m_unk0x4 = 0;
}

// STUB: LEGO1 0x10099e00
LegoAnimClassBase::~LegoAnimClassBase()
{
	// TODO
}

// STUB: LEGO1 0x10099e20
void LegoAnimClassBase::VTable0x4()
{
}

// STUB: LEGO1 0x10099e40
void LegoAnimClassBase::VTable0x8()
{
}

// STUB: LEGO1 0x10099f70
void LegoAnimClassBase::VTable0xc()
{
}

// FUNCTION: LEGO1 0x100a0b30
LegoAnimClass::LegoAnimClass()
{
	m_unk0x8 = 0;
	m_unk0xc = 0;
	m_unk0x10 = 0;
	m_unk0x14 = 0;
}

// STUB: LEGO1 0x100a0bc0
LegoAnimClass::~LegoAnimClass()
{
	// TODO
}

// STUB: LEGO1 0x100a0e30
void LegoAnimClass::VTable0x8()
{
}

// STUB: LEGO1 0x100a1040
void LegoAnimClass::VTable0xc()
{
}

// STUB: LEGO1 0x100a0c70
MxResult LegoAnimClass::VTable0x10()
{
	return SUCCESS;
}
