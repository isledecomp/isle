#include "bike.h"

#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoomni.h"
#include "legoutils.h"
#include "legoworld.h"
#include "misc.h"

DECOMP_SIZE_ASSERT(Bike, 0x164);

// FUNCTION: LEGO1 0x10076670
Bike::Bike()
{
	this->m_unk0x13c = 20.0;
	this->m_unk0x150 = 3.0;
	this->m_unk0x148 = 1;
}

// FUNCTION: LEGO1 0x100768f0
MxResult Bike::Create(MxDSAction& p_dsAction)
{
	MxResult result = IslePathActor::Create(p_dsAction);
	m_world = CurrentWorld();

	if (m_world) {
		m_world->Add(this);
	}

	return result;
}

// FUNCTION: LEGO1 0x10076920
void Bike::VTable0xe4()
{
	IslePathActor::VTable0xe4();
	GameState()->SetCurrentArea(LegoGameState::Area::e_bike);
	FUN_1003ee00(*g_isleScript, 11);
	FUN_1003ee00(*g_isleScript, 12);
	FUN_1003ee00(*g_isleScript, 15);
	FUN_1003ee00(*g_isleScript, 14);
	FUN_1003ee00(*g_isleScript, 13);
	ControlManager()->Unregister(this);
}

// STUB: LEGO1 0x100769a0
MxU32 Bike::VTable0xcc()
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10076aa0
MxU32 Bike::VTable0xd4(LegoControlManagerEvent& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10076b60
void Bike::FUN_10076b60()
{
	// TODO
}
