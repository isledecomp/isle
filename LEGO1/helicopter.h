#ifndef HELICOPTER_H
#define HELICOPTER_H

#include "helicopterstate.h"
#include "islepathactor.h"
#include "realtime/matrix.h"

class HelicopterSubclass {
public:
	inline HelicopterSubclass() : m_unk30(0) {}
	MxResult FUN_100040a0(Vector4Impl& p_v, float p_f);

private:
	Vector4Data m_unk0;
	Vector4Data m_unk18;
	undefined4 m_unk30;
};

// VTABLE: LEGO1 0x100d40f8
// SIZE 0x230
class Helicopter : public IslePathActor {
public:
	Helicopter();
	virtual ~Helicopter() override; // vtable+0x0

	// FUNCTION: LEGO1 0x10003070
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f0130
		return "Helicopter";
	}

	// FUNCTION: LEGO1 0x10003080
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, Helicopter::ClassName()) || IslePathActor::IsA(name);
	}

	virtual MxResult Create(MxDSObject& p_dsObject) override; // vtable+0x18
	virtual void VTable0xe4() override;
	virtual MxU32 VTable0xcc() override;
	virtual MxU32 VTable0xd4(MxType17NotificationParam& p) override;
	virtual MxU32 VTable0xd8(MxType18NotificationParam& p) override;
	void VTable0x74(Matrix4Impl& p_transform);
	void VTable0x70(float p);

	// SYNTHETIC: LEGO1 0x10003210
	// Helicopter::`scalar deleting destructor'

protected:
	Matrix4Data m_unk160;
	Matrix4Data m_unk1a8;
	float m_unk1f0;
	HelicopterSubclass m_unk1f4;
	HelicopterState* m_state;
	MxAtomId m_script;

private:
	void GetState();
};

#endif // HELICOPTER_H
