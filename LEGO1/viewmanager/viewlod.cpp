#include "viewlod.h"

// FUNCTION: LEGO1 0x100a5e40
// FUNCTION: BETA10 0x10171bdf
ViewLOD::~ViewLOD()
{
	if (m_meshBuilder) {
		delete m_meshBuilder;
	}
	// something else happens on BETA10 here
}
