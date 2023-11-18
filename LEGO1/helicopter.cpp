#include "helicopter.h"

#include "act3.h"
#include "legoanimationmanager.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoomni.h"
#include "legoutil.h"
#include "legoworld.h"

DECOMP_SIZE_ASSERT(Helicopter, 0x230)

// OFFSET: LEGO1 0x10001e60
Helicopter::Helicopter()
{
	m_unk13c = 60;
}

// OFFSET: LEGO1 0x10003230
Helicopter::~Helicopter()
{
	ControlManager()->Unregister(this);
	IslePathActor::Destroy(TRUE);
}

// OFFSET: LEGO1 0x100032c0
MxResult Helicopter::Create(MxDSObject& p_dsObject)
{
	MxResult result = IslePathActor::Create(p_dsObject);
	LegoWorld* world = GetCurrentWorld();
	SetWorld(world);
	if (world->IsA("Act3")) {
		((Act3*) GetWorld())->SetUnkown420c(this);
	}
	world = GetWorld();
	if (world)
		world->VTable0x58(this);
	GetState();
	return result;
}

// OFFSET: LEGO1 0x10003320
void Helicopter::GetState()
{
	m_state = (HelicopterState*) GameState()->GetState("HelicopterState");
	if (!m_state)
		m_state = (HelicopterState*) GameState()->CreateState("HelicopterState");
}

// OFFSET: LEGO1 0x10003360
void Helicopter::VTable0xe4()
{
	if (!GameState()->GetUnknown10()) {
		VTable0xe8(0x28, TRUE, 7);
	}
	IslePathActor::VTable0xe4();
	if (!GameState()->GetUnknown10()) {
		GameState()->SetUnknown424(0x3c);
		if (GetCurrentVehicle()) {
			if (GetCurrentVehicle()->IsA("IslePathActor")) {
				((IslePathActor*) GetCurrentVehicle())->VTable0xe8(0x37, TRUE, 7);
			}
		}
	}
	m_state->SetUnknown8(0);
	FUN_1003ee00(m_unk22c, 0x16);
	FUN_1003ee00(m_unk22c, 0x17);
	FUN_1003ee00(m_unk22c, 0x18);
	FUN_1003ee00(m_unk22c, 0x19);
	FUN_1003ee00(m_unk22c, 0x1a);
	FUN_1003ee00(m_unk22c, 0x1b);
	FUN_1003ee00(m_unk22c, 0x1c);
	FUN_1003ee00(m_unk22c, 0x1d);
	FUN_1003ee00(m_unk22c, 0x1e);
	FUN_1003ee00(m_unk22c, 0x1f);
	AnimationManager()->FUN_1005f6d0(TRUE);
	ControlManager()->Unregister(this);
}
