#ifndef MXMIDIPRESENTER_H
#define MXMIDIPRESENTER_H

#include "mxmusicpresenter.h"
#include "mxstreamchunk.h"

// VTABLE: LEGO1 0x100dca20
// SIZE 0x58
class MxMIDIPresenter : public MxMusicPresenter {
public:
	MxMIDIPresenter();
	~MxMIDIPresenter() override;

	// FUNCTION: LEGO1 0x100c2650
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x10101df8
		return "MxMIDIPresenter";
	}

	// FUNCTION: LEGO1 0x100c2660
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxMIDIPresenter::ClassName()) || MxMusicPresenter::IsA(p_name);
	}

	void ReadyTickle() override;             // vtable+0x18
	void StartingTickle() override;          // vtable+0x1c
	void StreamingTickle() override;         // vtable+0x20
	void DoneTickle() override;              // vtable+0x2c
	void Destroy() override;                 // vtable+0x38
	void EndAction() override;               // vtable+0x40
	MxResult PutData() override;             // vtable+0x4c
	void SetVolume(MxS32 p_volume) override; // vtable+0x60

	// SYNTHETIC: LEGO1 0x100c27a0
	// MxMIDIPresenter::`scalar deleting destructor'

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

protected:
	MxStreamChunk* m_chunk;
};

#endif // MXMIDIPRESENTER_H
