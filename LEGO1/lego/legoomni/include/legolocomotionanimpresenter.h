#ifndef LEGOLOCOMOTIONANIMPRESENTER_H
#define LEGOLOCOMOTIONANIMPRESENTER_H

#include "legoloopinganimpresenter.h"

// VTABLE: LEGO1 0x100d9170
// SIZE 0xd8
class LegoLocomotionAnimPresenter : public LegoLoopingAnimPresenter {
public:
	LegoLocomotionAnimPresenter();
	virtual ~LegoLocomotionAnimPresenter() override;

	// FUNCTION: LEGO1 0x1006ce50
	inline const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f06e4
		return "LegoLocomotionAnimPresenter";
	}

	// FUNCTION: LEGO1 0x1006ce60
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, ClassName()) || LegoLoopingAnimPresenter::IsA(p_name);
	}

	virtual void ReadyTickle() override;                          // vtable+0x18
	virtual void StartingTickle() override;                       // vtable+0x1c
	virtual void StreamingTickle() override;                      // vtable+0x20
	virtual MxResult AddToManager() override;                     // vtable+0x34
	virtual void Destroy() override;                              // vtable+0x38
	virtual void EndAction() override;                            // vtable+0x40
	virtual void PutFrame() override;                             // vtable+0x6c
	virtual MxResult VTable0x88(MxStreamChunk* p_chunk) override; // vtable+0x88

	// SYNTHETIC: LEGO1 0x1006cfe0
	// LegoLocomotionAnimPresenter::`scalar deleting destructor'

	inline void DecrementUnknown0xd4() { --m_unk0xd4; }

	inline undefined2 GetUnknown0xd4() { return m_unk0xd4; }

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	undefined4 m_unk0xc0;  // 0xc0
	undefined4* m_unk0xc4; // 0xc4
	MxCore* m_unk0xc8;     // 0xc8
	MxS32 m_unk0xcc;       // 0xcc
	MxS32 m_unk0xd0;       // 0xd0
	undefined2 m_unk0xd4;  // 0xd4
};

#endif // LEGOLOCOMOTIONANIMPRESENTER_H
