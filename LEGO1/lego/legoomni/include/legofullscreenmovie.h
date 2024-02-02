#ifndef LEGOFULLSCREENMOVIE_H
#define LEGOFULLSCREENMOVIE_H

#include "mxvariable.h"

// VTABLE: LEGO1 0x100d74b8
// SIZE 0x24
class LegoFullScreenMovie : public MxVariable {
public:
	LegoFullScreenMovie(const char* p_key, const char* p_value);
	void SetValue(const char* p_option) override;
};

#endif // LEGOFULLSCREENMOVIE_H
