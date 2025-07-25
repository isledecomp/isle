#ifndef MXVIDEOPRESENTER_H
#define MXVIDEOPRESENTER_H

#include "decomp.h"
#include "mxbitmap.h"
#include "mxgeometry.h"
#include "mxmediapresenter.h"

#include <ddraw.h>

// VTABLE: LEGO1 0x100d4be8
// SIZE 0x64
class MxVideoPresenter : public MxMediaPresenter {
public:
	MxVideoPresenter() { Init(); }

	// FUNCTION: LEGO1 0x1000c700
	// FUNCTION: BETA10 0x10054a80
	virtual void LoadHeader(MxStreamChunk* p_chunk) {} // vtable+0x5c

	// FUNCTION: LEGO1 0x1000c710
	// FUNCTION: BETA10 0x10054aa0
	virtual void CreateBitmap() {} // vtable+0x60

	virtual void NextFrame(); // vtable+0x64

	// FUNCTION: LEGO1 0x1000c720
	// FUNCTION: BETA10 0x10054ac0
	virtual void LoadFrame(MxStreamChunk* p_chunk) {} // vtable+0x68

	virtual void PutFrame(); // vtable+0x6c

	// FUNCTION: LEGO1 0x1000c730
	virtual void RealizePalette() {} // vtable+0x70

	virtual undefined VTable0x74(); // vtable+0x74

	// FUNCTION: LEGO1 0x1000c740
	~MxVideoPresenter() override { Destroy(TRUE); } // vtable+0x00

	// FUNCTION: LEGO1 0x1000c7a0
	void Destroy() override { Destroy(FALSE); } // vtable+0x38

	// FUNCTION: LEGO1 0x1000c7b0
	virtual LPDIRECTDRAWSURFACE GetSurface() { return m_surface; } // vtable+0x78

	// FUNCTION: LEGO1 0x1000c7c0
	virtual MxBool HasFrameBitmapOrAlpha() { return m_frameBitmap != NULL || m_alpha != NULL; } // vtable+0x7c

	// FUNCTION: LEGO1 0x1000c7e0
	virtual MxS32 GetWidth() { return m_alpha ? m_alpha->GetWidth() : m_frameBitmap->GetBmiWidth(); } // vtable+0x80

	// FUNCTION: LEGO1 0x1000c800
	virtual MxS32 GetHeight()
	{
		return m_alpha ? m_alpha->GetHeight() : m_frameBitmap->GetBmiHeightAbs();
	} // vtable+0x84

	// FUNCTION: BETA10 0x100551b0
	static const char* HandlerClassName()
	{
		// STRING: LEGO1 0x100f0760
		return "MxVideoPresenter";
	}

	// FUNCTION: LEGO1 0x1000c820
	// FUNCTION: BETA10 0x10055180
	const char* ClassName() const override // vtable+0x0c
	{
		return HandlerClassName();
	}

	// FUNCTION: LEGO1 0x1000c830
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxVideoPresenter::ClassName()) || MxMediaPresenter::IsA(p_name);
	}

	void ReadyTickle() override;                 // vtable+0x18
	void StartingTickle() override;              // vtable+0x1c
	void StreamingTickle() override;             // vtable+0x20
	void RepeatingTickle() override;             // vtable+0x24
	void FreezingTickle() override;              // vtable+0x28
	MxResult AddToManager() override;            // vtable+0x34
	void EndAction() override;                   // vtable+0x40
	MxResult PutData() override;                 // vtable+0x4c
	MxBool IsHit(MxS32 p_x, MxS32 p_y) override; // vtable+0x50

	// VTABLE: LEGO1 0x100dc2bc
	// SIZE 0x0c
	class AlphaMask {
	public:
		AlphaMask(const MxBitmap&);
		AlphaMask(const AlphaMask&);
		virtual ~AlphaMask();

		MxS32 IsHit(MxU32 p_x, MxU32 p_y);

		MxS32 GetWidth() const { return m_width; }
		MxS32 GetHeight() const { return m_height; }

		// SYNTHETIC: LEGO1 0x100b2650
		// MxVideoPresenter::AlphaMask::`scalar deleting destructor'

	private:
		MxU8* m_bitmask; // 0x00
		MxU16 m_width;   // 0x04
		MxU16 m_height;  // 0x08
	};

	inline MxS32 PrepareRects(RECT& p_rectDest, RECT& p_rectSrc);
	MxBitmap* GetBitmap() { return m_frameBitmap; }
	AlphaMask* GetAlphaMask() { return m_alpha; }

	// FUNCTION: BETA10 0x1002c2e0
	MxU8* GetBitmapStart(MxS32 p_left, MxS32 p_top) { return m_frameBitmap->GetStart(p_left, p_top); }

	void SetLoadedFirstFrame(BOOL p_loadedFirstFrame) { m_flags.m_bit0 = p_loadedFirstFrame; }
	void SetUseSurface(BOOL p_useSurface) { m_flags.m_bit1 = p_useSurface; }
	void SetUseVideoMemory(BOOL p_useVideoMemory) { m_flags.m_bit2 = p_useVideoMemory; }
	void SetDoNotWriteToSurface(BOOL p_doNotWriteToSurface) { m_flags.m_bit3 = p_doNotWriteToSurface; }
	void SetBitmapIsMap(BOOL p_bitmapIsMap) { m_flags.m_bit4 = p_bitmapIsMap; }

	BYTE LoadedFirstFrame() { return m_flags.m_bit0; }
	BYTE UseSurface() { return m_flags.m_bit1; }
	BYTE UseVideoMemory() { return m_flags.m_bit2; }
	BYTE DoNotWriteToSurface() { return m_flags.m_bit3; }
	BYTE BitmapIsMap() { return m_flags.m_bit4; }

	// SYNTHETIC: LEGO1 0x1000c910
	// MxVideoPresenter::`scalar deleting destructor'

private:
	void Init();

protected:
	void Destroy(MxBool p_fromDestructor);

	MxBitmap* m_frameBitmap;       // 0x50
	AlphaMask* m_alpha;            // 0x54
	LPDIRECTDRAWSURFACE m_surface; // 0x58
	MxS16 m_frameLoadTickleCount;  // 0x5c
	FlagBitfield m_flags;          // 0x5e
	MxLong m_frozenTime;           // 0x60
};

#endif // MXVIDEOPRESENTER_H
