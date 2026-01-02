#include "viewlod.h"

// FUNCTION: LEGO1 0x100a5e40
// STUB: BETA10 0x10171bdf
ViewLOD::~ViewLOD()
{
	// TODO: BETA10 mismatches
	if (m_meshBuilder) {
		delete m_meshBuilder;
	}
}
