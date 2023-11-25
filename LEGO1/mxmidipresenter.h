#ifndef MXMIDIPRESENTER_H
#define MXMIDIPRESENTER_H

#include "mxmusicpresenter.h"
#include "mxstreamchunk.h"

// VTABLE 0x100dca20
// SIZE 0x58
class MxMIDIPresenter : public MxMusicPresenter {
public:
	MxMIDIPresenter();
	virtual ~MxMIDIPresenter() override;

	// OFFSET: LEGO1 0x100c2650
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// 0x10101df8
		return "MxMIDIPresenter";
	}

	// OFFSET: LEGO1 0x100c2660
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxMIDIPresenter::ClassName()) || MxMusicPresenter::IsA(name);
	}

	virtual void ReadyTickle() override;             // vtable+0x18
	virtual void StartingTickle() override;          // vtable+0x1c
	virtual void StreamingTickle() override;         // vtable+0x20
	virtual void DoneTickle() override;              // vtable+0x2c
	virtual void Destroy() override;                 // vtable+0x38
	virtual void EndAction() override;               // vtable+0x40
	virtual undefined4 PutData() override;           // vtable+0x4c
	virtual void SetVolume(MxS32 p_volume) override; // vtable+0x60

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

protected:
	MxStreamChunk* m_chunk;
};

#endif // MXMIDIPRESENTER_H
