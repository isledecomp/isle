#ifndef MXVIDEOPRESENTER_H
#define MXVIDEOPRESENTER_H

#include "decomp.h"
#include "mxbitmap.h"
#include "mxmediapresenter.h"

// VTABLE 0x100d4be8
// SIZE 0x64
class MxVideoPresenter : public MxMediaPresenter {
public:
	enum {
		Flag_Bit1 = 0x01,
	};

	MxVideoPresenter() { Init(); }
	virtual ~MxVideoPresenter() override; // vtable+0x0

	// OFFSET: LEGO1 0x1000c820
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f0760
		return "MxVideoPresenter";
	}

	// OFFSET: LEGO1 0x1000c830
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxVideoPresenter::ClassName()) || MxMediaPresenter::IsA(name);
	}

	void Init();
	void Destroy(MxBool p_fromDestructor);

	virtual void ReadyTickle() override;                 // vtable+0x18
	virtual void StartingTickle() override;              // vtable+0x1c
	virtual void StreamingTickle() override;             // vtable+0x20
	virtual void RepeatingTickle() override;             // vtable+0x24
	virtual void Unk5Tickle() override;                  // vtable+0x28
	virtual MxResult AddToManager() override;            // vtable+0x34
	virtual void Destroy() override;                     // vtable+0x38
	virtual void EndAction() override;                   // vtable+0x40
	virtual undefined4 PutData() override;               // vtable+0x4c
	virtual MxBool IsHit(MxS32 p_x, MxS32 p_y) override; // vtable+0x50
	virtual void VTable0x5c(MxStreamChunk* p_chunk);     // vtable+0x5c
	virtual void VTable0x60();                           // vtable+0x60
	virtual void VTable0x64();                           // vtable+0x64
	virtual void VTable0x68(MxStreamChunk* p_chunk);     // vtable+0x68
	virtual void VTable0x6c();                           // vtable+0x6c
	virtual void VTable0x70();                           // vtable+0x70
	virtual undefined VTable0x74();                      // vtable+0x74
	virtual LPDIRECTDRAWSURFACE VTable0x78();            // vtable+0x78
	virtual MxBool VTable0x7c();                         // vtable+0x7c
	virtual MxS32 GetWidth();                            // vtable+0x80
	virtual MxS32 GetHeight();                           // vtable+0x84

	// SIZE 0xc
	struct AlphaMask {
		MxU8* m_bitmask;
		MxU16 m_width;
		MxU16 m_height;

		AlphaMask(const MxBitmap&);
		AlphaMask(const AlphaMask&);
		virtual ~AlphaMask();

		MxS32 IsHit(MxU32 p_x, MxU32 p_y);
	};

	MxBitmap* m_bitmap;          // 0x50
	AlphaMask* m_alpha;          // 0x54
	LPDIRECTDRAWSURFACE m_unk58; // 0x58
	MxS16 m_unk5c;               // 0x5c
	MxU8 m_flags;                // 0x5e
	MxLong m_unk60;              // 0x60
};

#endif // MXVIDEOPRESENTER_H
