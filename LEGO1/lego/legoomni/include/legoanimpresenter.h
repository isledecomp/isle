#ifndef LEGOANIMPRESENTER_H
#define LEGOANIMPRESENTER_H

#include "anim/legoanim.h"
#include "legoroilist.h"
#include "mxgeometry/mxgeometry3d.h"
#include "mxvideopresenter.h"

class LegoWorld;
class LegoAnimClass;

// VTABLE: LEGO1 0x100d90c8
// SIZE 0xc0
class LegoAnimPresenter : public MxVideoPresenter {
public:
	enum {
		c_bit2 = 0x02
	};

	LegoAnimPresenter();
	~LegoAnimPresenter() override;

	// FUNCTION: LEGO1 0x10068530
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f071c
		return "LegoAnimPresenter";
	}

	// FUNCTION: LEGO1 0x10068540
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoAnimPresenter::ClassName()) || MxVideoPresenter::IsA(p_name);
	}

	void ReadyTickle() override;                                                           // vtable+0x18
	void StartingTickle() override;                                                        // vtable+0x1c
	void StreamingTickle() override;                                                       // vtable+0x20
	void DoneTickle() override;                                                            // vtable+0x2c
	void ParseExtra() override;                                                            // vtable+0x30
	MxResult AddToManager() override;                                                      // vtable+0x34
	void Destroy() override;                                                               // vtable+0x38
	MxResult StartAction(MxStreamController* p_controller, MxDSAction* p_action) override; // vtable+0x3c
	void EndAction() override;                                                             // vtable+0x40
	void PutFrame() override;                                                              // vtable+0x6c
	virtual MxResult CreateAnim(MxStreamChunk* p_chunk);                                   // vtable+0x88
	virtual void VTable0x8c();                                                             // vtable+0x8c
	virtual void VTable0x90();                                                             // vtable+0x90
	virtual void VTable0x94();                                                             // vtable+0x94
	virtual void VTable0x98();                                                             // vtable+0x98

	// STUB: LEGO1 0x1000c990
	virtual void VTable0x9c() {} // vtable+0x9c

	virtual void VTable0xa0(); // vtable+0xa0

	inline LegoAnim* GetAnimation() { return m_anim; }

	const char* GetActionObjectName();

protected:
	void Init();
	void Destroy(MxBool p_fromDestructor);
	LegoChar* FUN_10069150(const LegoChar* p_und1);
	void FUN_100692b0();
	void FUN_100695c0();
	LegoChar* FUN_100697c0(const LegoChar* p_und1, const LegoChar* p_und2);
	LegoBool FUN_100698b0(const CompoundObject& p_rois, const LegoChar* p_und2);
	void FUN_10069b10();
	LegoBool FUN_1006aba0();
	LegoBool FUN_1006abb0(LegoTreeNode*, undefined4);
	void FUN_1006ac90();
	void FUN_1006c8a0(LegoBool);

	LegoAnim* m_anim;          // 0x64
	undefined4* m_unk0x68;     // 0x68
	undefined4 m_unk0x6c;      // 0x6c
	LegoROIList* m_unk0x70;    // 0x70
	LegoROIList* m_unk0x74;    // 0x74
	MxMatrix* m_unk0x78;       // 0x78
	undefined4 m_unk0x7c;      // 0x7c
	LegoWorld* m_currentWorld; // 0x80
	MxAtomId m_animAtom;       // 0x84
	undefined4 m_unk0x88;      // 0x88
	undefined4 m_unk0x8c;      // 0x8c
	undefined4 m_unk0x90;      // 0x90
	undefined m_unk0x94;       // 0x94
	undefined m_unk0x95;       // 0x95
	MxBool m_unk0x96;          // 0x96
	undefined m_unk0x97;       // 0x97
	undefined4 m_unk0x98;      // 0x98
	MxS16 m_unk0x9c;           // 0x9c
	undefined4 m_unk0xa0;      // 0xa0
	undefined4 m_unk0xa4;      // 0xa4
	Mx3DPointFloat m_unk0xa8;  // 0xa8
	undefined4 m_unk0xbc;      // 0xbc
};

// SYNTHETIC: LEGO1 0x10068650
// LegoAnimPresenter::`scalar deleting destructor'

#endif // LEGOANIMPRESENTER_H
