class LegoPathTag0 {};

#include "legopathboundary.h"

// This translation unit exists to supply ONE out-of-line member of the
// LegoPathActorSet red-black tree. Retail emits that member from a
// separate object, and it only reproduces byte-exactly when it is compiled in
// its own translation unit -- two of these members in one unit are never
// simultaneously exact. The declarations above the include are a stand-in for
// the 1997 source text that occupied this file; replace them if it is ever
// recovered.

// clang-format off
// MSVC 4.20 parses `>>` as a shift, so the closing angle brackets must stay split.
typedef _Tree<
	LegoPathActor*,
	LegoPathActor*,
	LegoPathActorSet::_Kfn,
	LegoPathActorSetCompare,
	allocator<LegoPathActor*>
> PathActorTree;
// clang-format on

struct PathActorDecProbe : public PathActorTree {
	typedef void (iterator::*Fn)();
	static Fn Get();
};

PathActorDecProbe::Fn PathActorDecProbe::Get()
{
	return &iterator::_Dec;
}
