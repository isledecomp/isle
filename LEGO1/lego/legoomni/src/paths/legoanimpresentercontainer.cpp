class LegoAnimPresenterTag0 {};

#include "legopathboundary.h"

// This translation unit exists to supply two out-of-line members of the
// LegoAnimPresenterSet red-black tree. Retail emits them from a separate
// object, and they only reproduce byte-exactly when compiled in their own
// translation unit, in this order. The declaration above the include is a
// stand-in for the 1997 source text that occupied this file; replace it if it
// is ever recovered.

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

struct AnimPresenterRangeProbe : public AnimPresenterTree {
	typedef _Pairii (AnimPresenterTree::*Fn)(const key_type&);
	static Fn Get();
};

AnimPresenterRangeProbe::Fn AnimPresenterRangeProbe::Get()
{
	return &AnimPresenterTree::equal_range;
}

struct AnimPresenterInsertNodeProbe : public AnimPresenterTree {
	typedef iterator (AnimPresenterTree::*Fn)(_Nodeptr, _Nodeptr, const value_type&);
	static Fn Get();
};

AnimPresenterInsertNodeProbe::Fn AnimPresenterInsertNodeProbe::Get()
{
	return &AnimPresenterTree::_Insert;
}
