#ifndef REGISTRATIONBOOK_H
#define REGISTRATIONBOOK_H

#include "legoworld.h"

// VTABLE: LEGO1 0x100d9928
// SIZE 0x2d0
class RegistrationBook : public LegoWorld {
public:
	RegistrationBook();
	virtual ~RegistrationBook() override; // vtable+0x00

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x04
	virtual MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x10076e10
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f04c8
		return "RegistrationBook";
	}

	// FUNCTION: LEGO1 0x10076e20
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, RegistrationBook::ClassName()) || LegoWorld::IsA(p_name);
	}

	virtual MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	virtual void ReadyWorld() override;                       // vtable+0x50
	virtual MxBool VTable0x64() override;                     // vtable+0x64
	virtual void VTable0x68(MxBool p_add) override;           // vtable+0x68

	// SYNTHETIC: LEGO1 0x10076f30
	// RegistrationBook::`scalar deleting destructor'
private:
	undefined4 m_unk0xf8;  // 0xf8
	undefined m_unk0xfc;  // 0xfc
	undefined m_unk0xfd[0x192]; // 0xfd
	undefined4 m_unk0x280;  // 0x280
	undefined4 m_unk0x284;  // 0x284
	undefined4 m_unk0x288;  // 0x288
	undefined2 m_unk0x28c;  // 0x28c
	undefined2 m_unk0x28e;  // 0x28e
	undefined2 m_unk0x2b8;  // 0x2b8
	undefined m_unk0x2ba[0x02]; // 0x2ba
	undefined4 m_unk0x2bc;  // 0x2bc
	undefined m_unk0x2c1;  // 0x2c1
	undefined m_unk0x2c2[0x02]; // 0x2c2
	undefined4 m_unk0x2c4;  // 0x2c4
	undefined4 m_unk0x2c8;  // 0x2c8
	undefined4 m_unk0x2cc;  // 0x2cc
};

#endif // REGISTRATIONBOOK_H
