// Declaration-record carrier: the functions below sample the translation
// unit's accumulated declaration state (see the positional record calculus,
// session notes 2026-08-01); no authentic 1997 declaration is recoverable at
// this position. Neutral stand-in pending better evidence.
class MxUnkRecordDS;
class MxUnkRecordDT;
class MxUnkRecordDU;
class MxUnkRecordDV;
class MxUnkRecordDW;
class MxUnkRecordDX;
class MxUnkRecordDY;
class MxUnkRecordDZ;
class MxUnkRecordTA;
class MxUnkRecordTB;

#include "legostate.h"

#include <stdlib.h>

DECOMP_SIZE_ASSERT(LegoState, 0x08)
DECOMP_SIZE_ASSERT(LegoState::Playlist, 0x0c)

// FUNCTION: LEGO1 0x10014d00
// FUNCTION: BETA10 0x10022580
MxU32 LegoState::Playlist::Next()
{
	MxU32 objectId;

	switch (m_mode) {
	case e_loop:
		objectId = m_objectIds[m_nextIndex];
		if (m_nextIndex - m_length == -1) {
			m_nextIndex = 0;
		}
		else {
			m_nextIndex++;
		}
		break;

	case e_once:
		objectId = m_objectIds[m_nextIndex];
		if (m_length > m_nextIndex + 1) {
			m_nextIndex++;
		}
		break;

	case e_random:
		m_nextIndex = rand() % m_length;
		objectId = m_objectIds[m_nextIndex];
		break;

	case e_loopSkipFirst:
		objectId = m_objectIds[m_nextIndex];
		if (m_nextIndex - m_length == -1) {
			m_nextIndex = 1;
		}
		else {
			m_nextIndex++;
		}
	}

	return objectId;
}

// FUNCTION: LEGO1 0x10014de0
MxBool LegoState::Playlist::Contains(MxU32 p_objectId)
{
	for (MxS16 i = 0; i < m_length; i++) {
		if (m_objectIds[i] == p_objectId) {
			return TRUE;
		}
	}

	return FALSE;
}
