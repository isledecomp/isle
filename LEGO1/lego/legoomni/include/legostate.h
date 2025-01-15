#ifndef LEGOSTATE_H
#define LEGOSTATE_H

#include "decomp.h"
#include "misc/legostorage.h"
#include "mxcore.h"

// VTABLE: LEGO1 0x100d46c0
// VTABLE: BETA10 0x101b89d8
// SIZE 0x08
class LegoState : public MxCore {
public:
	enum ScoreColor {
		e_grey = 0,
		e_yellow,
		e_blue,
		e_red
	};

	// SIZE 0x0c
	struct Playlist {
		enum Mode {
			e_loop,
			e_once,
			e_random,
			e_loopSkipFirst
		};

		// FUNCTION: LEGO1 0x10017c00
		// FUNCTION: BETA10 0x10031dc0
		Playlist()
		{
			m_objectIds = NULL;
			m_length = 0;
			m_mode = e_loop;
			m_nextIndex = 0;
		}

		// FUNCTION: BETA10 0x10031e10
		Playlist(MxU32* p_objectIds, MxS16 p_length, MxS16 p_mode)
		{
			m_objectIds = p_objectIds;
			m_length = p_length;
			m_mode = p_mode;
			m_nextIndex = 0;
		}

		// FUNCTION: LEGO1 0x10071800
		// FUNCTION: BETA10 0x10031e70
		Playlist& operator=(const Playlist& p_playlist)
		{
			m_objectIds = p_playlist.m_objectIds;
			m_length = p_playlist.m_length;
			m_nextIndex = p_playlist.m_nextIndex;
			m_mode = p_playlist.m_mode;
			return *this;
		}

		MxU32 Next();
		MxBool Contains(MxU32 p_objectId);

		MxU32* m_objectIds; // 0x00
		MxS16 m_length;     // 0x04
		MxS16 m_mode;       // 0x06
		MxS16 m_nextIndex;  // 0x08
	};

	// FUNCTION: LEGO1 0x10005f40
	~LegoState() override {}

	// FUNCTION: LEGO1 0x10005f90
	virtual MxBool IsSerializable() { return TRUE; } // vtable+0x14

	// FUNCTION: LEGO1 0x10005fa0
	virtual MxBool Reset() { return FALSE; } // vtable+0x18

	// FUNCTION: LEGO1 0x10005fb0
	// FUNCTION: BETA10 0x10017af0
	virtual MxResult Serialize(LegoFile* p_file)
	{
		if (p_file->IsWriteMode()) {
			p_file->Write(MxString(ClassName()));
		}
		return SUCCESS;
	} // vtable+0x1c

	// FUNCTION: LEGO1 0x100060d0
	// FUNCTION: BETA10 0x10017d20
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f01b8
		// STRING: BETA10 0x101dcdac
		return "LegoState";
	}

	// FUNCTION: LEGO1 0x100060e0
	// FUNCTION: BETA10 0x100a9000
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoState::ClassName()) || MxCore::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x10006160
	// LegoState::`scalar deleting destructor'
};

#endif // LEGOSTATE_H
