#include "skateboard.h"

#include "decomp.h"
#include "isle_actions.h"
#include "jukebox_actions.h"
#include "legoanimationmanager.h"
#include "legoutils.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "pizza.h"

DECOMP_SIZE_ASSERT(SkateBoard, 0x168)

// FUNCTION: LEGO1 0x1000fd40
SkateBoard::SkateBoard()
{
	m_unk0x160 = 0;
	m_unk0x13c = 15.0;
	m_unk0x150 = 3.5;
	m_unk0x148 = 1;

	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x1000ff80
SkateBoard::~SkateBoard()
{
	ControlManager()->Unregister(this);
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x10010000
MxResult SkateBoard::Create(MxDSAction& p_dsAction)
{
	MxResult result = IslePathActor::Create(p_dsAction);

	if (result == SUCCESS) {
		m_world = CurrentWorld();
		m_world->Add(this);
		// The type `Pizza` is an educated guesss, inferred from VTable0xe4() below
		Pizza* findResult = (Pizza*) CurrentWorld()->Find(*g_isleScript, IsleScript::c_Pizza_Actor);
		if (findResult) {
			findResult->SetUnknown0x84((undefined*) this);
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10010050
void SkateBoard::VTable0xe4()
{
	// TODO: Work out what kind of structure this points to
	if (*(int*) (m_unk0x164 + 0x18) == 3) {
		Pizza* pizza = (Pizza*) CurrentWorld()->Find(*g_isleScript, IsleScript::c_Pizza_Actor);
		pizza->FUN_10038380();
		pizza->FUN_100382b0();
		m_unk0x160 = 0;
	}
	IslePathActor::VTable0xe4();
	GameState()->m_currentArea = LegoGameState::Area::e_skateboard;
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_SkateArms_Ctl);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_SkatePizza_Bitmap);
	ControlManager()->Unregister(this);
}

// STUB: LEGO1 0x100100e0
MxU32 SkateBoard::VTable0xcc()
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x10010230
MxU32 SkateBoard::VTable0xd4(LegoControlManagerEvent& p_param)
{
	MxU32 result = 0;

	if (p_param.GetUnknown0x28() == 1 && p_param.GetClickedObjectId() == 0xc3) {
		VTable0xe4();
		GameState()->m_currentArea = LegoGameState::Area::e_unk66;
		result = 1;
	}

	return result;
}

// FUNCTION: LEGO1 0x10010270
void SkateBoard::FUN_10010270(undefined4 param_1)
{
	MxCore* pMVar3;

	m_act1state = (Act1State*) GameState()->GetState("Act1State");
	if (!m_act1state) {
		this->m_act1state = (Act1State*) GameState()->CreateState("Act1State");
	}
	pMVar3 = this->m_world->Find(*g_isleScript, IsleScript::c_SkatePizza_Bitmap);
	if (pMVar3) {
		// I have no idea what this is. Need a call with vtable offset 0x54 and one 4 byte argument
		((LegoActor*)pMVar3)->VTable0x54(param_1);

	} else {
		if (this->m_unk0x160 != '\0') {
			MxNotificationParam local_1c = MxNotificationParam(c_notificationType0, NULL);
			NotificationManager()->Send(this, local_1c);
		}
	}
}
MxU32 SkateBoard::VTable0xd0()
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x10010510
void SkateBoard::FUN_10010510()
{
  char *pcVar1;

  if (*(int *)(m_unk0x164 + 0x18) != 3) {
    PlayMusic(JukeboxScript::c_BeachBlvd_Music);
    pcVar1 = (char *)(m_unk0x164 + 0x22);
    if (*pcVar1 == '\0') {
      *pcVar1 = '\x01';
      MxMatrix x = MxMatrix(CurrentActor()->GetROI()->GetLocal2World());
	  float xs = x[2][0] * 2.5;
	  float y = x[2][1] + 0.2;
	  float z = x[2][2] * 2.5;
	  x.TranslateBy(&xs, &y, &z);
      AnimationManager()->FUN_10060dc0(IsleScript::c_sns008in_RunAnim, &x,'\x01','\0',NULL,0,TRUE,TRUE,'\x01');
    }
  }
  return;
}
