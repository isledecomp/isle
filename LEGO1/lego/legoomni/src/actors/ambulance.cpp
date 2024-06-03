#include "ambulance.h"

#include "decomp.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legovariables.h"
#include "legoworld.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxticklemanager.h"
#include "mxtimer.h"
#include "mxvariabletable.h"
#include "scripts.h"

DECOMP_SIZE_ASSERT(Ambulance, 0x184)
DECOMP_SIZE_ASSERT(AmbulanceMissionState, 0x24)

// FUNCTION: LEGO1 0x10035ee0
Ambulance::Ambulance()
{
	m_unk0x168 = 0;
	m_unk0x16a = -1;
	m_state = NULL;
	m_unk0x16c = 0;
	m_unk0x174 = -1;
	m_unk0x16e = 0;
	m_unk0x178 = -1;
	m_unk0x170 = 0;
	m_unk0x172 = 0;
	m_unk0x13c = 40.0;
	m_unk0x17c = 1.0;
}

// FUNCTION: LEGO1 0x10035f90
void Ambulance::Destroy(MxBool p_fromDestructor)
{
}

// FUNCTION: LEGO1 0x10036150
Ambulance::~Ambulance()
{
	ControlManager()->Unregister(this);
	TickleManager()->UnregisterClient(this);
}

// FUNCTION: LEGO1 0x100361d0
MxResult Ambulance::Create(MxDSAction& p_dsAction)
{
	MxResult result = IslePathActor::Create(p_dsAction);

	if (result == SUCCESS) {
		m_world = CurrentWorld();

		if (m_world) {
			m_world->Add(this);
		}

		m_state = (AmbulanceMissionState*) GameState()->GetState("AmbulanceMissionState");
		if (!m_state) {
			m_state = new AmbulanceMissionState();
			m_state->m_unk0x08 = 0;
			GameState()->RegisterState(m_state);
		}
	}

	VariableTable()->SetVariable(g_varAMBULFUEL, "1.0");
	m_unk0x17c = 1.0;
	m_time = Timer()->GetTime();
	return result;
}

// STUB: LEGO1 0x10036300
void Ambulance::VTable0x70(float p_float)
{
	// TODO
}

// FUNCTION: LEGO1 0x100363f0
void Ambulance::CreateState()
{
	LegoGameState* gameState = GameState();
	AmbulanceMissionState* state = (AmbulanceMissionState*) gameState->GetState("AmbulanceMissionState");

	if (state == NULL) {
		state = (AmbulanceMissionState*) gameState->CreateState("AmbulanceMissionState");
	}

	m_state = state;
}

// STUB: LEGO1 0x10036420
MxLong Ambulance::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10036860
MxU32 Ambulance::VTable0xdc(MxType19NotificationParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10036ce0
MxU32 Ambulance::HandleClick()
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10036e60
void Ambulance::FUN_10036e60()
{
	// TODO
}

// STUB: LEGO1 0x10036e90
void Ambulance::VTable0xe4()
{
	// TODO
}

// STUB: LEGO1 0x10036f90
MxU32 Ambulance::HandleControl(LegoControlManagerEvent& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10037060
void Ambulance::FUN_10037060()
{
	// TODO
}

// STUB: LEGO1 0x10037160
MxResult Ambulance::Tickle()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10037240
void Ambulance::FUN_10037240()
{
	// TODO
}

// STUB: LEGO1 0x10037250
void Ambulance::FUN_10037250()
{
	// TODO
}

// FUNCTION: LEGO1 0x100373a0
AmbulanceMissionState::AmbulanceMissionState()
{
	m_unk0x10 = 0;
	m_unk0x12 = 0;
	m_unk0x14 = 0;
	m_unk0x08 = 0;
	m_unk0x16 = 0;
	m_unk0x0c = 0;
	m_unk0x18 = 0;
	m_score1 = 0;
	m_score2 = 0;
	m_score3 = 0;
	m_score4 = 0;
	m_score5 = 0;
}

// STUB: LEGO1 0x10037440
MxResult AmbulanceMissionState::Serialize(LegoFile* p_legoFile)
{
	// TODO
	return LegoState::Serialize(p_legoFile);
}
