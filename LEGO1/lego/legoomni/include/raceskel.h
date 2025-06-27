#ifndef RACESKEL_H
#define RACESKEL_H

#include "legoanimactor.h"

// VTABLE: LEGO1 0x100d93f8 LegoPathActor
// VTABLE: LEGO1 0x100d94c8 LegoAnimActor
// VTABLE: BETA10 0x101bf9d0 LegoPathActor
// VTABLE: BETA10 0x101bfac0 LegoAnimActor
// SIZE 0x178
class RaceSkel : public LegoAnimActor {
public:
	RaceSkel();
	~RaceSkel() override;

	void ParseAction(char* p_extra) override; // vtable+0x20

	MxResult AnimateWithTransform(float p_time, Matrix4& p_transform) override;

	virtual void FUN_10071c80(Vector3& p_vec);

	void GetCurrentAnimData(float* p_outCurAnimPosition, float* p_outCurAnimDuration);

	// SYNTHETIC: LEGO1 0x10071cf0
	// RaceSkel::`scalar deleting destructor'

private:
	float m_animPosition; // 0x1c
};

// GLOBAL: LEGO1 0x100d93f0
// RaceSkel::`vbtable'

#endif // RACESKEL_H
