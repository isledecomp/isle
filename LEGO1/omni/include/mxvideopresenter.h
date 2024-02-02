#ifndef MXVIDEOPRESENTER_H
#define MXVIDEOPRESENTER_H

#include "decomp.h"
#include "mxbitmap.h"
#include "mxmediapresenter.h"
#include "mxrect32.h"

// VTABLE: LEGO1 0x100d4be8
// SIZE 0x64
class MxVideoPresenter : public MxMediaPresenter {
public:
	MxVideoPresenter() { Init(); }

	// FUNCTION: LEGO1 0x1000c740
	~MxVideoPresenter() override { Destroy(TRUE); } // vtable+0x00

	// FUNCTION: LEGO1 0x1000c820
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0760
		return "MxVideoPresenter";
	}

	// FUNCTION: LEGO1 0x1000c830
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxVideoPresenter::ClassName()) || MxMediaPresenter::IsA(p_name);
	}

	void ReadyTickle() override;      // vtable+0x18
	void StartingTickle() override;   // vtable+0x1c
	void StreamingTickle() override;  // vtable+0x20
	void RepeatingTickle() override;  // vtable+0x24
	void Unk5Tickle() override;       // vtable+0x28
	MxResult AddToManager() override; // vtable+0x34

	// FUNCTION: LEGO1 0x1000c7a0
	void Destroy() override { Destroy(FALSE); } // vtable+0x38

	void EndAction() override;                   // vtable+0x40
	MxResult PutData() override;                 // vtable+0x4c
	MxBool IsHit(MxS32 p_x, MxS32 p_y) override; // vtable+0x50

	// FUNCTION: LEGO1 0x1000c700
	virtual void LoadHeader(MxStreamChunk* p_chunk){}; // vtable+0x5c

	// FUNCTION: LEGO1 0x1000c710
	virtual void CreateBitmap(){}; // vtable+0x60

	virtual void NextFrame(); // vtable+0x64

	// FUNCTION: LEGO1 0x1000c720
	virtual void LoadFrame(MxStreamChunk* p_chunk){}; // vtable+0x68

	virtual void PutFrame(); // vtable+0x6c

	// FUNCTION: LEGO1 0x1000c730
	virtual void RealizePalette(){}; // vtable+0x70

	virtual undefined VTable0x74(); // vtable+0x74

	// FUNCTION: LEGO1 0x1000c7b0
	virtual LPDIRECTDRAWSURFACE VTable0x78() { return m_unk0x58; } // vtable+0x78

	// FUNCTION: LEGO1 0x1000c7c0
	virtual MxBool VTable0x7c() { return m_bitmap != NULL || m_alpha != NULL; } // vtable+0x7c

	// FUNCTION: LEGO1 0x1000c7e0
	virtual MxS32 GetWidth() { return m_alpha ? m_alpha->m_width : m_bitmap->GetBmiWidth(); } // vtable+0x80

	// FUNCTION: LEGO1 0x1000c800
	virtual MxS32 GetHeight() { return m_alpha ? m_alpha->m_height : m_bitmap->GetBmiHeightAbs(); } // vtable+0x84

	// VTABLE: LEGO1 0x100dc2bc
	// SIZE 0x0c
	struct AlphaMask {
		MxU8* m_bitmask;
		MxU16 m_width;
		MxU16 m_height;

		AlphaMask(const MxBitmap&);
		AlphaMask(const AlphaMask&);
		virtual ~AlphaMask();

		MxS32 IsHit(MxU32 p_x, MxU32 p_y);

		// SYNTHETIC: LEGO1 0x100b2650
		// MxVideoPresenter::AlphaMask::`scalar deleting destructor'
	};

	inline MxS32 PrepareRects(MxRect32& p_rectDest, MxRect32& p_rectSrc);
	inline MxBitmap* GetBitmap() { return m_bitmap; }
	inline AlphaMask* GetAlphaMask() { return m_alpha; }

	inline void SetBit0(BOOL p_e) { m_flags.m_bit0 = p_e; }
	inline void SetBit1(BOOL p_e) { m_flags.m_bit1 = p_e; }
	inline void SetBit2(BOOL p_e) { m_flags.m_bit2 = p_e; }
	inline void SetBit3(BOOL p_e) { m_flags.m_bit3 = p_e; }
	inline void SetBit4(BOOL p_e) { m_flags.m_bit4 = p_e; }

	inline BYTE GetBit0() { return m_flags.m_bit0; }
	inline BYTE GetBit1() { return m_flags.m_bit1; }
	inline BYTE GetBit2() { return m_flags.m_bit2; }
	inline BYTE GetBit3() { return m_flags.m_bit3; }
	inline BYTE GetBit4() { return m_flags.m_bit4; }

	// SYNTHETIC: LEGO1 0x1000c910
	// MxVideoPresenter::`scalar deleting destructor'

private:
	void Init();

protected:
	void Destroy(MxBool p_fromDestructor);

	MxBitmap* m_bitmap;            // 0x50
	AlphaMask* m_alpha;            // 0x54
	LPDIRECTDRAWSURFACE m_unk0x58; // 0x58
	MxS16 m_unk0x5c;               // 0x5c
	FlagBitfield m_flags;          // 0x5e
	MxLong m_unk0x60;              // 0x60
};

#endif // MXVIDEOPRESENTER_H
