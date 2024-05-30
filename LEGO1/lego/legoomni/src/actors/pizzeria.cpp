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
#include "pizzamissionstate.h"
#include "pizzeriastate.h"
#include "scripts.h"

DECOMP_SIZE_ASSERT(Pizzeria, 0x84)

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
undefined4 Pizzeria::HandleClick()
{
	if (FUN_1003ef60() && m_pizzaMissionState->m_unk0x0c == 0) {
		if (CurrentActor()->GetActorId() != GameState()->GetActorId()) {
			if (!CurrentActor()->IsA("SkateBoard")) {
				((IslePathActor*) CurrentActor())->VTable0xe4();
			}
		}

		AnimationManager()->FUN_10061010(FALSE);

		Pizza* pizza = (Pizza*) CurrentWorld()->Find(*g_isleScript, IsleScript::c_Pizza_Actor);
		pizza->FUN_10038220(m_pizzeriaState->FUN_10017d70());
	}

	return 1;
}
