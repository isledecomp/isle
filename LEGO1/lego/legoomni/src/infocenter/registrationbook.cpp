#include "registrationbook.h"

#include "legoomni.h"

// STUB: LEGO1 0x10076d20
RegistrationBook::RegistrationBook()
{
	// TODO
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
void RegistrationBook::VTable0x50()
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
