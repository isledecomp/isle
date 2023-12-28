#ifndef MXVIDEOPRESENTER_H
#define MXVIDEOPRESENTER_H

#include "decomp.h"
#include "mxbitmap.h"
#include "mxmediapresenter.h"

// VTABLE: LEGO1 0x100d4be8
// SIZE 0x64
class MxVideoPresenter : public MxMediaPresenter {
public:
	enum {
		Flag_Bit1 = 0x01,
		Flag_Bit2 = 0x02,
		Flag_Bit3 = 0x04,
		Flag_Bit4 = 0x08,
		Flag_Bit5 = 0x10,
	};

	MxVideoPresenter() { Init(); }
	virtual ~MxVideoPresenter() override; // vtable+0x0

	// FUNCTION: LEGO1 0x1000c820
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0760
		return "MxVideoPresenter";
	}

	// FUNCTION: LEGO1 0x1000c830
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxVideoPresenter::ClassName()) || MxMediaPresenter::IsA(p_name);
	}

	virtual void ReadyTickle() override;                 // vtable+0x18
	virtual void StartingTickle() override;              // vtable+0x1c
	virtual void StreamingTickle() override;             // vtable+0x20
	virtual void RepeatingTickle() override;             // vtable+0x24
	virtual void Unk5Tickle() override;                  // vtable+0x28
	virtual MxResult AddToManager() override;            // vtable+0x34
	virtual void Destroy() override;                     // vtable+0x38
	virtual void EndAction() override;                   // vtable+0x40
	virtual MxResult PutData() override;                 // vtable+0x4c
	virtual MxBool IsHit(MxS32 p_x, MxS32 p_y) override; // vtable+0x50
	virtual void LoadHeader(MxStreamChunk* p_chunk);     // vtable+0x5c
	virtual void CreateBitmap();                         // vtable+0x60
	virtual void NextFrame();                            // vtable+0x64
	virtual void LoadFrame(MxStreamChunk* p_chunk);      // vtable+0x68
	virtual void VTable0x6c();                           // vtable+0x6c
	virtual void RealizePalette();                       // vtable+0x70
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

	inline MxBitmap* GetBitmap() { return m_bitmap; }

private:
	void Init();

protected:
	void Destroy(MxBool p_fromDestructor);

	MxBitmap* m_bitmap;            // 0x50
	AlphaMask* m_alpha;            // 0x54
	LPDIRECTDRAWSURFACE m_unk0x58; // 0x58
	MxS16 m_unk0x5c;               // 0x5c
	MxU8 m_flags;                  // 0x5e
	MxLong m_unk0x60;              // 0x60
};

#endif // MXVIDEOPRESENTER_H
