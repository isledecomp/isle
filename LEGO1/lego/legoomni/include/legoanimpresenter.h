#ifndef LEGOANIMPRESENTER_H
#define LEGOANIMPRESENTER_H

#include "mxgeometry/mxgeometry3d.h"
#include "mxvideopresenter.h"

class LegoWorld;
class LegoMemoryStream;
class LegoAnimClass;

// VTABLE: LEGO1 0x100d90c8
class LegoAnimPresenter : public MxVideoPresenter {
public:
	LegoAnimPresenter();
	virtual ~LegoAnimPresenter() override;

	// FUNCTION: LEGO1 0x10068530
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f071c
		return "LegoAnimPresenter";
	}

	// FUNCTION: LEGO1 0x10068540
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoAnimPresenter::ClassName()) || MxVideoPresenter::IsA(p_name);
	}

	virtual void ReadyTickle() override;                                     // vtable+0x18
	virtual void StartingTickle() override;                                  // vtable+0x1c
	virtual void StreamingTickle() override;                                 // vtable+0x20
	virtual void ParseExtra() override;                                      // vtable+0x30
	virtual void Destroy() override;                                         // vtable+0x38
	virtual MxResult StartAction(MxStreamController*, MxDSAction*) override; // vtable+0x3c
	virtual void EndAction() override;                                       // vtable+0x40
	virtual void PutFrame();                                                 // vtable+0x6c
	virtual MxS32 VTable0x88(MxStreamChunk* p_chunk);                        // vtable+0x88

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	LegoAnimClass* m_unk0x64;  // 0x64
	undefined4 m_unk0x68;      // 0x68
	undefined4 m_unk0x6c;      // 0x6c
	undefined4 m_unk0x70;      // 0x70
	undefined4 m_unk0x74;      // 0x74
	undefined4 m_unk0x78;      // 0x78
	undefined4 m_unk0x7c;      // 0x7c
	LegoWorld* m_currentWorld; // 0x80
	MxAtomId m_animAtom;       // 0x84
	undefined4 m_unk0x88;      // 0x88
	undefined4 m_unk0x8c;      // 0x8c
	undefined4 m_unk0x90;      // 0x90
	undefined m_unk0x94;       // 0x94
	undefined m_unk0x95;       // 0x95
	undefined m_unk0x96;       // 0x96
	undefined m_unk0x97;       // 0x97
	undefined4 m_unk0x98;      // 0x98
	MxS16 m_unk0x9c;           // 0x9f
	undefined4 m_unk0xa0;      // 0xa0
	undefined4 m_unk0xa4;      // 0xa4
	Mx3DPointFloat m_vec;      // 0xa8
	undefined4 m_unk0xbc;      // 0xbc
};

// SYNTHETIC: LEGO1 0x10068650
// LegoAnimPresenter::`scalar deleting destructor'

// VTABLE: LEGO1 0x100db768
class LegoAnimClassBase {
public:
	LegoAnimClassBase();
	virtual ~LegoAnimClassBase();

	virtual void VTable0x4();
	virtual void VTable0x8();
	virtual void VTable0xc();

	undefined4 m_unk0x4;
};

// SYNTHETIC: LEGO1 0x10099e00
// LegoAnimClassBase::`scalar deleting destructor'

// VTABLE: LEGO1 0x100db8d8
class LegoAnimClass : public LegoAnimClassBase {
public:
	LegoAnimClass();
	virtual ~LegoAnimClass() override;

	virtual void VTable0x8() override;
	virtual void VTable0xc() override;
	virtual MxResult VTable0x10(LegoMemoryStream* p_stream, MxS32);

	undefined4 m_unk0x8;
	undefined4 m_unk0xc;
	undefined4 m_unk0x10;
	undefined4 m_unk0x14;
};

// SYNTHETIC: LEGO1 0x100a0ba0
// LegoAnimClass::`scalar deleting destructor'

#endif // LEGOANIMPRESENTER_H
