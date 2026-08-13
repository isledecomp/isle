#include "legopathboundary.h"

// This translation unit exists to supply ONE out-of-line member of the
// LegoAnimPresenterSet red-black tree. Retail emits that member from a
// separate object, and it only reproduces byte-exactly when it is compiled in
// its own translation unit -- two of these members in one unit are never
// simultaneously exact.

// clang-format off
// MSVC 4.20 parses `>>` as a shift, so the closing angle brackets must stay split.
typedef _Tree<
	LegoAnimPresenter*,
	LegoAnimPresenter*,
	LegoAnimPresenterSet::_Kfn,
	LegoAnimPresenterSetCompare,
	allocator<LegoAnimPresenter*>
> AnimPresenterTree;
// clang-format on

struct AnimPresenterFindProbe : public AnimPresenterTree {
	typedef const_iterator (AnimPresenterTree::*Fn)(const key_type&) const;
	static Fn Get();
};

AnimPresenterFindProbe::Fn AnimPresenterFindProbe::Get()
{
	return &AnimPresenterTree::find;
}
