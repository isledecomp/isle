#include "registrationbook.h"

#include "infocenterstate.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "mxnotificationmanager.h"

DECOMP_SIZE_ASSERT(RegistrationBook, 0x2d0)

// FUNCTION: LEGO1 0x10076d20
RegistrationBook::RegistrationBook() : m_unk0xf8(0x80000000), m_unk0xfc(1)
{
	memset(m_unk0x100, 0, sizeof(m_unk0x100));
	memset(m_unk0x168, 0, sizeof(m_unk0x168));

	// Maybe not be part of the struct, but then it would need packing
	m_unk0x280.m_unk0x0e = 0;

	memset(m_unk0x290, 0, sizeof(m_unk0x290));
	memset(&m_unk0x280, -1, sizeof(m_unk0x280) - 2);

	m_unk0x2b8 = 0;
	m_infocenterState = NULL;

	NotificationManager()->Register(this);

	m_unk0x2c1 = 0;
	m_unk0x2c4 = 0;
	m_unk0x2c8 = 0;
	m_unk0x2cc = 0;
}

// STUB: LEGO1 0x10076f50
RegistrationBook::~RegistrationBook()
{
	// TODO
}

// FUNCTION: LEGO1 0x10077060
MxResult RegistrationBook::Create(MxDSAction& p_dsAction)
{
	MxResult result = LegoWorld::Create(p_dsAction);
	if (result == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
		SetIsWorldActive(FALSE);
		InputManager()->Register(this);

		GameState()->SetCurrentArea(12);
		GameState()->StopArea(0);

		m_infocenterState = (InfocenterState*) GameState()->GetState("InfocenterState");
	}
	return result;
}

// STUB: LEGO1 0x100770e0
MxLong RegistrationBook::Notify(MxParam& p_param)
{
	// TODO

	return 0;
}

// STUB: LEGO1 0x10077cc0
void RegistrationBook::ReadyWorld()
{
	// TODO
}

// STUB: LEGO1 0x10077fd0
MxResult RegistrationBook::Tickle()
{
	// TODO
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10078180
void RegistrationBook::Enable(MxBool p_enable)
{
	LegoWorld::Enable(p_enable);

	if (p_enable) {
		InputManager()->SetWorld(this);
		SetIsWorldActive(FALSE);
	}
	else {
		if (InputManager()->GetWorld() == this) {
			InputManager()->ClearWorld();
		}
	}
}

// FUNCTION: LEGO1 0x100783e0
MxBool RegistrationBook::VTable0x64()
{
	DeleteObjects(&m_atom, 500, 506);
	return TRUE;
}
