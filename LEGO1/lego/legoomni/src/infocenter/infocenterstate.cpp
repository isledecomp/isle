#include "infocenterstate.h"

DECOMP_SIZE_ASSERT(InfocenterState, 0x94);

// FUNCTION: LEGO1 0x10071600
InfocenterState::InfocenterState()
{
	// TODO
	memset(m_buffer, 0, sizeof(m_buffer));
}

// FUNCTION: LEGO1 0x10071920
InfocenterState::~InfocenterState()
{
	MxS16 i = 0;
	do {
		if (GetInfocenterBufferElement(i) != NULL) {
			delete GetInfocenterBufferElement(i)->GetAction();
			delete GetInfocenterBufferElement(i);
		}
		i++;
	} while (i < GetInfocenterBufferSize());
}
