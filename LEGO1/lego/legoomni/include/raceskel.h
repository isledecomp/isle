#ifndef RACESKEL_H
#define RACESKEL_H

#include "legoanimactor.h"

/*
	VTABLE: LEGO1 0x100d7668 LegoPathActor
	VTABLE: LEGO1 0x100d7738 LegoAnimActor
*/
// SIZE 0x178
class RaceSkel : public LegoAnimActor {
public:
	RaceSkel();

	void GetCurrentAnimData(float* p_outCurAnimPosition, float* p_outCurAnimDuration);

private:
	float m_animPosition; // 0x1c
};

#endif // RACESKEL_H
