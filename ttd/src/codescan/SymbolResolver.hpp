#ifndef CODESCAN_SYMBOLRESOLVER_HPP
#define CODESCAN_SYMBOLRESOLVER_HPP

#include <TTD/IReplayEngine.h>

namespace ttd {
    // Resolve one named export in the image mapped at `moduleBase`, for either PE format.
    // `is64Bit`, when given, receives the image's bitness -- which is how a caller knows
    // which calling convention the resolved function's arguments follow. In a WoW64 trace
    // the same module name is loaded twice, once in each width, so this cannot be taken
    // from the trace as a whole.
    TTD::GuestAddress ResolveExport(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBase,
                                    const char* exportName, bool* is64Bit = nullptr);
}

#endif
