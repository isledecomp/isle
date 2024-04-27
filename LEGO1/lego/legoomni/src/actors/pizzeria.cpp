#include "pizzeria.h"

#include "legogamestate.h"
#include "misc.h"

DECOMP_SIZE_ASSERT(Pizzeria, 0x84)

// FUNCTION: LEGO1 0x100179c0
MxResult Pizzeria::Create(MxDSAction& p_dsAction)
{
	MxResult result = IsleActor::Create(p_dsAction);

	if (result == SUCCESS) {
		Init();
	}

	return result;
}

// FUNCTION: LEGO1 0x100179f0
void Pizzeria::Init()
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

// STUB: LEGO1 0x10017a50
undefined4 Pizzeria::VTable0x68()
{
	// TODO
	return 0;
}
