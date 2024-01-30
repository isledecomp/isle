#include "registrationbook.h"

#include "legoomni.h"

#include "mxnotificationmanager.h"

// STUB: LEGO1 0x10076d20
RegistrationBook::RegistrationBook()
{
	this->m_unk0xf8 = 0x80000000;
	this->m_unk0xfc = 1;
	this->m_unk0x28e = 0;
	this->m_unk0x280 = -1;
	this->m_unk0x284 = -1;
	this->m_unk0x288 = -1;
	this->m_unk0x28c = -1;
	this->m_unk0x2b8 = 0;
	this->m_unk0x2bc = 0;
	this->m_unk0x2c1 = 0;
	this->m_unk0x2c4 = 0;
	this->m_unk0x2c8 = 0;
	this->m_unk0x2cc = 0;

	NotificationManager()->Register(this);
}

// STUB: LEGO1 0x10076f50
RegistrationBook::~RegistrationBook()
{
	// TODO
}

// STUB: LEGO1 0x10077060
MxResult RegistrationBook::Create(MxDSAction& p_dsAction)
{
	return SUCCESS;
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

// STUB: LEGO1 0x10078180
void RegistrationBook::VTable0x68(MxBool p_add)
{
	// TODO
}

// FUNCTION: LEGO1 0x100783e0
MxBool RegistrationBook::VTable0x64()
{
	DeleteObjects(&m_atom, 500, 506);
	return TRUE;
}
