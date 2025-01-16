#include "pizzeria.h"

#include "isle_actions.h"
#include "islepathactor.h"
#include "legoanimationmanager.h"
#include "legogamestate.h"
#include "legopathactor.h"
#include "legoutils.h"
#include "legoworld.h"
#include "misc.h"
#include "pizza.h"
#include "scripts.h"

DECOMP_SIZE_ASSERT(Pizzeria, 0x84)
DECOMP_SIZE_ASSERT(PizzeriaState, 0x58)

// GLOBAL: LEGO1 0x100f0ce8
IsleScript::Script PizzeriaState::g_pepperActions[] =
	{IsleScript::c_ppz107ma_RunAnim, IsleScript::c_ppz114pa_RunAnim, IsleScript::c_ppz114pa_RunAnim};

// GLOBAL: LEGO1 0x100f0cf8
IsleScript::Script PizzeriaState::g_mamaActions[] =
	{IsleScript::c_ppz001pe_RunAnim, IsleScript::c_ppz006pa_RunAnim, IsleScript::c_ppz007pa_RunAnim};

// GLOBAL: LEGO1 0x100f0d08
IsleScript::Script PizzeriaState::g_papaActions[] =
	{IsleScript::c_ppz054ma_RunAnim, IsleScript::c_ppz055ma_RunAnim, IsleScript::c_ppz056ma_RunAnim};

// GLOBAL: LEGO1 0x100f0d18
IsleScript::Script PizzeriaState::g_nickActions[] =
	{IsleScript::c_ppz031ma_RunAnim, IsleScript::c_ppz035pa_RunAnim, IsleScript::c_ppz036pa_RunAnim};

// GLOBAL: LEGO1 0x100f0d28
IsleScript::Script PizzeriaState::g_lauraActions[] =
	{IsleScript::c_ppz075pa_RunAnim, IsleScript::c_ppz082pa_RunAnim, IsleScript::c_ppz084pa_RunAnim};

// FUNCTION: LEGO1 0x100179c0
MxResult Pizzeria::Create(MxDSAction& p_dsAction)
{
	MxResult result = IsleActor::Create(p_dsAction);

	if (result == SUCCESS) {
		CreateState();
	}

	return result;
}

// FUNCTION: LEGO1 0x100179f0
// FUNCTION: BETA10 0x100efbfc
void Pizzeria::CreateState()
{
	LegoGameState* gameState = GameState();
	PizzeriaState* pizzeriaState = (PizzeriaState*) gameState->GetState("PizzeriaState");
	if (pizzeriaState == NULL) {
		pizzeriaState = (PizzeriaState*) gameState->CreateState("PizzeriaState");
	}
	m_pizzeriaState = pizzeriaState;

	gameState = GameState();
	PizzaMissionState* pizzaMissionState = (PizzaMissionState*) gameState->GetState("PizzaMissionState");
	if (pizzaMissionState == NULL) {
		pizzaMissionState = (PizzaMissionState*) gameState->CreateState("PizzaMissionState");
	}
	m_pizzaMissionState = pizzaMissionState;
}

// FUNCTION: LEGO1 0x10017a50
// FUNCTION: BETA10 0x100efc91
MxLong Pizzeria::HandleClick()
{
	if (FUN_1003ef60() && m_pizzaMissionState->m_unk0x0c == 0) {
		if (UserActor()->GetActorId() != GameState()->GetActorId()) {
			if (!UserActor()->IsA("SkateBoard")) {
				((IslePathActor*) UserActor())->Exit();
			}
		}

		AnimationManager()->FUN_10061010(FALSE);

		Pizza* pizza = (Pizza*) CurrentWorld()->Find(*g_isleScript, IsleScript::c_Pizza_Actor);
		pizza->FUN_10038220((IsleScript::Script) m_pizzeriaState->NextAction());
	}

	return 1;
}

// FUNCTION: LEGO1 0x10017af0
// FUNCTION: BETA10 0x100efd14
PizzeriaState::PizzeriaState()
{
	m_unk0x08[0] = Playlist((MxU32*) g_pepperActions, sizeOfArray(g_pepperActions), Playlist::e_once);
	m_unk0x08[1] = Playlist((MxU32*) g_mamaActions, sizeOfArray(g_mamaActions), Playlist::e_once);
	m_unk0x08[2] = Playlist((MxU32*) g_papaActions, sizeOfArray(g_papaActions), Playlist::e_once);
	m_unk0x08[3] = Playlist((MxU32*) g_nickActions, sizeOfArray(g_nickActions), Playlist::e_once);
	m_unk0x08[4] = Playlist((MxU32*) g_lauraActions, sizeOfArray(g_lauraActions), Playlist::e_once);
	memset(m_unk0x44, -1, sizeof(m_unk0x44));
}

// FUNCTION: LEGO1 0x10017d50
MxS16 PizzeriaState::FUN_10017d50()
{
	return m_unk0x44[GameState()->GetActorId() - 1];
}

// FUNCTION: LEGO1 0x10017d70
// FUNCTION: BETA10 0x100effc0
MxU32 PizzeriaState::NextAction()
{
	MxU8 actorId = GameState()->GetActorId();

	if (m_unk0x44[actorId - 1] < 2) {
		m_unk0x44[actorId - 1]++;
	}

	return m_unk0x08[actorId - 1].Next();
}

// FUNCTION: LEGO1 0x10017da0
// FUNCTION: BETA10 0x100efe33
MxResult PizzeriaState::Serialize(LegoStorage* p_storage)
{
	MxResult res = LegoState::Serialize(p_storage);

	if (p_storage->IsReadMode()) {
		for (MxS16 i = 0; i < 5; i++) {
			p_storage->ReadS16(m_unk0x08[i].m_nextIndex);
		}
	}
	else {
		for (MxS16 i = 0; i < 5; i++) {
			p_storage->WriteS16(m_unk0x08[i].m_nextIndex);
		}
	}

	return res;
}
