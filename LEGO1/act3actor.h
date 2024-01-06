#ifndef ACT3ACTOR_H
#define ACT3ACTOR_H

#include "mxcore.h"

// FIXME: Uncertain location. There are three vtables which eventually call this
//        class' ClassName() function, but none of them call it directly.
class Act3Actor : public MxCore {
public:
	// FUNCTION: LEGO1 0x100431b0
	inline virtual const char* ClassName() const override
	{
		// STRING: LEGO1 0x100f03ac
		return "Act3Actor";
	}
};

#endif // ACT3ACTOR_H
