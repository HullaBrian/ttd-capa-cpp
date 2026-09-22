#include "abi.hpp"

#include <cstdio>
#include <cstring>

using ttdcapa::win32meta::ArgKind;
using ttdcapa::win32meta::AuxKind;

namespace ttdcapa {
    namespace {

        // A dereference is only worth attempting above the first 64 KiB; the null
        // page and its neighbours are never mapped in user mode.
        constexpr uint64_t kMinDerefAddr = 0x10000;

        // Guards against a mis-typed count parameter turning into a huge read.
        constexpr uint64_t kMaxCountElements = 1u << 20;

        // Every x86 stack argument occupies a whole number of 4-byte words.
        constexpr uint16_t kX86StackAlign = 4;

        // Matches win32meta's MAX_PARAMS; the index never emits more.
        constexpr size_t kMaxParams = 32;

        // All-or-nothing: a partially recovered scalar or GUID is worse than none.
        // readRecordedRun follows recorded-range seams, so a value the guest wrote in
        // two pieces now reads whole instead of failing here.
        bool readGuest(MemorySource const& src, uint64_t addr, void* dst, size_t size) {
            if (addr < kMinDerefAddr || size == 0) {
                return false;
            }
            return readRecordedRun(src, addr, dst, size) == size;
        }

    }  // namespace

    // True for the kinds that are a pointer in the guest, whatever they point at.
    bool isPlainStringKind(ArgKind kind) {
        return kind == ArgKind::AnsiString || kind == ArgKind::WideString;
    }

    bool isPointerKind(ArgKind kind) {
        switch (kind) {
            case ArgKind::AnsiString:
            case ArgKind::WideString:
            case ArgKind::AnsiBuffer:
            case ArgKind::WideBuffer:
            case ArgKind::ByteBuffer:
            case ArgKind::PtrToInt:
            case ArgKind::StructPtr:
            case ArgKind::FuncPtr:
            case ArgKind::Guid:
            case ArgKind::Pointer:
            case ArgKind::PtrToAnsiString:
            case ArgKind::PtrToWideString:
            case ArgKind::CountedAnsiString:
            case ArgKind::CountedWideString:
            case ArgKind::Handle:  // opaque but pointer-sized
                return true;
            default:
                return false;
        }
    }

    namespace {

        bool typeNameIs(const win32meta::ParamSig& p, const char* name) {
            return p.type != nullptr && std::strcmp(p.type, name) == 0;
        }

        // An aggregate the x64 ABI passes by hidden pointer but x86 pushes by value.
        // The index cannot tell us its x86 footprint -- it records the x64 size, which
        // is wrong for any struct holding a pointer -- so its presence makes the whole
        // signature unlayoutable on x86. The display type is the discriminator: a real
        // pointer parameter renders as "OVERLAPPED*", an array as "WSABUF[]", and a
        // by-value one as "VARIANT". Arrays matter here because the metadata classifies
        // an array of a large struct as StructPtr too, and one of those is a pointer on
        // both ABIs -- reading it as by-value would decline half the socket API.
        bool isByValueAggregate(const win32meta::ParamSig& p) {
            if (p.kind != ArgKind::StructPtr) {
                return false;
            }
            size_t len = p.type != nullptr ? std::strlen(p.type) : 0;
            if (len == 0) {
                return true;
            }
            if (p.type[len - 1] == '*') {
                return false;
            }
            return !(len >= 2 && p.type[len - 2] == '[' && p.type[len - 1] == ']');
        }

        // Bytes one parameter occupies on the x86 argument stack, or 0 if unknowable.
        uint16_t x86StackFootprint(const win32meta::ParamSig& p) {
            // A builder that knows the answer says so, and nothing below can improve
            // on that. build-phnt-index.py fills this in for every parameter; the
            // win32json builder cannot, and leaves it zero for the inference below.
            if (p.x86Footprint != 0) {
                return static_cast<uint16_t>((p.x86Footprint + kX86StackAlign - 1)
                                             / kX86StackAlign * kX86StackAlign);
            }
            if (isByValueAggregate(p)) {
                return 0;
            }
            uint16_t size = 4;
            switch (p.kind) {
                case ArgKind::Float:
                    size = 4;
                    break;
                case ArgKind::Double:
                    size = 8;
                    break;
                case ArgKind::Integer:
                case ArgKind::Enum:
                case ArgKind::Bool:
                    // For scalars the index stores the value's own width here -- but
                    // computed for x64, where a pointer-sized scalar is 8 bytes and on
                    // x86 is 4. An 8 here is therefore ambiguous on its own: Int64
                    // really does push 8 bytes on x86, UIntPtr pushes 4.
                    //
                    // The display name settles it whenever the metadata resolved the
                    // parameter to a primitive, which is the common case and covers the
                    // SIZE_T/ULONG_PTR/DWORD_PTR family -- win32json flattens all of
                    // those to UIntPtr, so VirtualAlloc, VirtualProtect, HeapAlloc,
                    // WriteProcessMemory and CreateThread all lay out exactly rather
                    // than falling back to the heuristic. Only a named typedef the
                    // metadata kept intact (WPARAM, LPARAM) stays genuinely unknown,
                    // and guessing there would silently shift every later parameter --
                    // so decline and let the caller fall back to the heuristic.
                    //
                    // Removing that last gap means having the builder emit the x86
                    // footprint alongside the x64 one; there is a spare pad byte in the
                    // parameter record for it.
                    if (p.pointeeSize == 8) {
                        if (typeNameIs(p, "UIntPtr") || typeNameIs(p, "IntPtr")) {
                            size = 4;  // pointer-sized by definition: 4 bytes on a 32-bit guest
                            break;
                        }
                        if (typeNameIs(p, "UInt64") || typeNameIs(p, "Int64")) {
                            size = 8;  // genuinely 64-bit, and pushed as 8 bytes on x86 too
                            break;
                        }
                        return 0;
                    }
                    size = (p.pointeeSize >= 1 && p.pointeeSize < 8) ? p.pointeeSize : 4;
                    break;
                default:
                    size = 4;  // pointers, handles, and anything unclassified
                    break;
            }
            return static_cast<uint16_t>((size + kX86StackAlign - 1) / kX86StackAlign * kX86StackAlign);
        }

        // Byte offset of each parameter from the first argument on the x86 stack.
        // Returns false when any parameter's footprint is unknown, in which case every
        // offset after it would be wrong and the signature must not be used.
        bool computeStackOffsets(const win32meta::FuncSig& sig, uint16_t (&offsets)[kMaxParams]) {
            // `slot` is the positional ABI index and is already shifted for a hidden
            // return pointer, which on x86 is simply the first pushed argument. Walk in
            // slot order so a shifted signature still lays out correctly.
            uint16_t running[kMaxParams] = {};
            uint16_t footprint[kMaxParams] = {};
            uint8_t maxSlot = 0;

            for (uint8_t i = 0; i < sig.paramCount && i < kMaxParams; ++i) {
                const win32meta::ParamSig& p = sig.params[i];
                if (p.slot >= kMaxParams) {
                    return false;
                }
                uint16_t bytes = x86StackFootprint(p);
                if (bytes == 0) {
                    return false;
                }
                footprint[p.slot] = bytes;
                maxSlot = p.slot > maxSlot ? p.slot : maxSlot;
            }

            // A hidden return pointer occupies slot 0 without appearing in the
            // parameter list, so fill any gap with a pointer-sized push.
            uint16_t offset = 0;
            for (uint8_t s = 0; s <= maxSlot && s < kMaxParams; ++s) {
                running[s] = offset;
                offset += footprint[s] != 0 ? footprint[s] : kX86StackAlign;
            }

            for (uint8_t i = 0; i < sig.paramCount && i < kMaxParams; ++i) {
                offsets[i] = running[sig.params[i].slot];
            }
            return true;
        }

        // The value of parameter `index`, from wherever its architecture puts it.
        uint64_t fetchArg(const CallFrame& frame, const win32meta::FuncSig& sig, uint8_t index,
                          const uint16_t (&x86Offsets)[kMaxParams], bool& ok) {
            const win32meta::ParamSig& p = sig.params[index];
            ok = true;

            if (frame.arch == GuestArch::X86) {
                // At the callee's first instruction ESP points at the return address,
                // so the arguments begin one word above it.
                uint64_t addr = static_cast<uint64_t>(frame.x86->Esp) + kX86StackAlign + x86Offsets[index];
                uint64_t v = 0;
                size_t width = p.kind == ArgKind::Double ? 8 : 4;
                ok = readGuest(frame.thread, addr, &v, width);
                return v;
            }

            const AMD64_CONTEXT& ctx = *frame.x64;
            if (p.slot < 4) {
                if (p.isFloat()) {
                    const M128BIT* xmm[4] = { &ctx.Xmm0, &ctx.Xmm1, &ctx.Xmm2, &ctx.Xmm3 };
                    return xmm[p.slot]->Low;
                }
                const uint64_t gpr[4] = { ctx.Rcx, ctx.Rdx, ctx.R8, ctx.R9 };
                return gpr[p.slot];
            }
            // Above the shadow space the caller reserved for RCX/RDX/R8/R9.
            uint64_t addr = ctx.Rsp + 0x28 + static_cast<uint64_t>(p.slot - 4) * 8;
            uint64_t v = 0;
            ok = readGuest(frame.thread, addr, &v, sizeof(v));
            return v;
        }

        double floatValue(const win32meta::ParamSig& p, uint64_t bits) {
            if (p.kind == ArgKind::Float) {
                float f = 0.0f;
                uint32_t lo = static_cast<uint32_t>(bits);
                std::memcpy(&f, &lo, sizeof(f));
                return static_cast<double>(f);
            }
            double d = 0.0;
            std::memcpy(&d, &bits, sizeof(d));
            return d;
        }

        // Widen a pointee of `size` bytes to 64 bits.
        uint64_t narrowRead(const uint8_t* raw, uint16_t size) {
            uint64_t v = 0;
            std::memcpy(&v, raw, size > 8 ? 8 : size);
            return v;
        }

        // `fallbackWidth` is what to read when the metadata did not pin the pointee
        // down -- the guest's pointer width, since an untyped pointee is usually one.
        bool derefScalar(MemorySource const& src, uint64_t ptr, uint16_t size,
                         uint16_t fallbackWidth, uint64_t& out) {
            uint16_t width = size == 0 ? fallbackWidth : (size > 8 ? 8 : size);
            uint8_t buf[8] = {};
            if (!readGuest(src, ptr, buf, width)) {
                return false;
            }
            out = narrowRead(buf, width);
            return true;
        }

        std::string formatGuid(const uint8_t* b) {
            char buf[40];
            std::snprintf(buf, sizeof(buf),
                          "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                          static_cast<unsigned long>(narrowRead(b, 4)),
                          static_cast<unsigned>(narrowRead(b + 4, 2)),
                          static_cast<unsigned>(narrowRead(b + 6, 2)),
                          b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
            return buf;
        }

        bool isBufferKind(ArgKind kind) {
            return kind == ArgKind::AnsiBuffer || kind == ArgKind::WideBuffer || kind == ArgKind::ByteBuffer;
        }

        // How many bytes a counted buffer parameter spans, or 0 when we can't tell.
        // `args` supplies the sibling parameter the count lives in -- after a return
        // pass those may themselves have been filled in, which is exactly what makes
        // ReadFile's lpBuffer renderable at its *actual* length.
        uint64_t resolveByteCount(const win32meta::ParamSig& p, const std::vector<DecodedArg>& args) {
            uint64_t count = 0;
            switch (p.auxKind) {
                case AuxKind::CountConst:
                    count = static_cast<uint64_t>(p.auxValue);
                    break;
                case AuxKind::BytesFromParam:
                case AuxKind::CountFromParam: {
                    if (p.auxValue < 0 || static_cast<size_t>(p.auxValue) >= args.size()) {
                        return 0;
                    }
                    const DecodedArg& src = args[static_cast<size_t>(p.auxValue)];
                    count = src.has_deref ? src.deref : src.raw;
                    break;
                }
                case AuxKind::None:
                default:
                    return 0;
            }
            if (count == 0 || count > kMaxCountElements) {
                return 0;
            }
            if (p.auxKind == AuxKind::BytesFromParam) {
                return count;
            }
            uint16_t elem = p.pointeeSize ? p.pointeeSize : 1;
            return count * elem;
        }

        // Length of `buf` up to and including its first `charWidth`-wide NUL. A
        // character buffer's count parameter is the caller's *capacity*, so without
        // this the report would carry a few hundred bytes of unrelated stack memory
        // after every out-string.
        size_t terminatorEnd(const std::vector<uint8_t>& buf, size_t charWidth) {
            for (size_t i = 0; i + charWidth <= buf.size(); i += charWidth) {
                bool nul = true;
                for (size_t k = 0; k < charWidth; ++k) {
                    if (buf[i + k] != 0) {
                        nul = false;
                        break;
                    }
                }
                if (nul) {
                    return i + charWidth;
                }
            }
            return buf.size();
        }

        // Read a counted buffer into `arg`, capped at opt.max_buffer. Character
        // buffers additionally get a textual rendering, since that's what a rule or
        // an analyst actually wants to see.
        void captureBuffer(MemorySource const& src, const DecodeOptions& opt,
                           ArgKind kind, uint64_t ptr, uint64_t byteCount, DecodedArg& arg) {
            if (ptr < kMinDerefAddr || byteCount == 0) {
                return;
            }
            size_t want = static_cast<size_t>(byteCount < opt.max_buffer ? byteCount : opt.max_buffer);
            std::vector<uint8_t> buf(want);
            // A buffer the guest filled in several passes is recorded as several
            // ranges; one query would stop at the first seam and drop the rest.
            size_t got = readRecordedRun(src, ptr, buf.data(), want);
            if (got == 0) {
                return;
            }
            buf.resize(got);

            if (kind == ArgKind::AnsiBuffer) {
                bool cut = false;
                if (auto s = readAnsiString(src, ptr, got, &cut)) {
                    arg.str = std::move(*s);
                    arg.has_str = !arg.str.empty();
                    arg.str_truncated = arg.has_str && cut;
                }
                buf.resize(terminatorEnd(buf, 1));
            } else if (kind == ArgKind::WideBuffer) {
                bool cut = false;
                if (auto s = readWideString(src, ptr, got / sizeof(wchar_t), &cut)) {
                    arg.str = std::move(*s);
                    arg.has_str = !arg.str.empty();
                    arg.str_truncated = arg.has_str && cut;
                }
                buf.resize(terminatorEnd(buf, 2));
            }
            arg.bytes = std::move(buf);
        }

        // Everything that needs the callee to have run. Shared by the entry pass
        // (for [In] parameters, which are already valid) and the return pass.
        void dereference(MemorySource const& src, const DecodeOptions& opt,
                         ArgKind kind, uint64_t ptr, uint16_t pointeeSize, uint16_t pointerSize,
                         uint64_t byteCount, DecodedArg& arg) {
            switch (kind) {
                case ArgKind::AnsiString:
                    if (auto s = readAnsiString(src, ptr, opt.max_string, &arg.str_truncated)) {
                        arg.str = std::move(*s);
                        arg.has_str = true;
                    }
                    break;
                case ArgKind::WideString:
                    if (auto s = readWideString(src, ptr, opt.max_string, &arg.str_truncated)) {
                        arg.str = std::move(*s);
                        arg.has_str = true;
                    }
                    break;
                case ArgKind::PtrToInt: {
                    // An 8-byte pointee on a 32-bit guest is almost always a
                    // pointer-sized type the index measured at x64 width -- HANDLE*,
                    // SIZE_T*, ULONG_PTR* and friends. Reading 8 bytes there splices
                    // the following dword into the value, so trust the guest's width
                    // instead. A genuine 64-bit pointee (LONGLONG*) loses its high
                    // half, which is still better than a value mixed with unrelated
                    // memory. Telling the two apart needs the index to carry 32-bit
                    // sizes; see the README.
                    uint16_t eff = (pointerSize == 4 && pointeeSize == 8) ? 4 : pointeeSize;
                    uint64_t v = 0;
                    if (derefScalar(src, ptr, eff, pointerSize, v)) {
                        arg.deref = v;
                        arg.has_deref = true;
                    }
                    break;
                }
                case ArgKind::PtrToAnsiString:
                case ArgKind::PtrToWideString: {
                    // The pointee here is itself a pointer, so its width is the guest's.
                    uint64_t inner = 0;
                    if (!derefScalar(src, ptr, pointerSize, pointerSize, inner)) {
                        break;
                    }
                    arg.deref = inner;
                    arg.has_deref = true;
                    auto s = (kind == ArgKind::PtrToAnsiString)
                        ? readAnsiString(src, inner, opt.max_string, &arg.str_truncated)
                        : readWideString(src, inner, opt.max_string, &arg.str_truncated);
                    if (s) {
                        arg.str = std::move(*s);
                        arg.has_str = true;
                    }
                    break;
                }
                case ArgKind::CountedAnsiString:
                case ArgKind::CountedWideString: {
                    // {USHORT Length; USHORT MaximumLength; PCHAR/PWSTR Buffer;}
                    //
                    // The native API carries almost all of its text this way, and
                    // Length is in *bytes* for both variants. The buffer need not be
                    // NUL-terminated, so it is read by count rather than scanned --
                    // the whole reason this is a kind of its own rather than a
                    // pointer that happens to land near some characters.
                    uint16_t lengthBytes = 0;
                    if (!readGuest(src, ptr, &lengthBytes, sizeof(lengthBytes))) {
                        break;
                    }
                    // Buffer sits at the first pointer-aligned offset after the two
                    // USHORTs: 8 on x64 (there is padding), 4 on x86.
                    uint64_t bufferPtr = 0;
                    uint64_t bufferOffset = pointerSize == 8 ? 8 : 4;
                    if (!derefScalar(src, ptr + bufferOffset, pointerSize, pointerSize, bufferPtr)) {
                        break;
                    }
                    arg.deref = bufferPtr;
                    arg.has_deref = true;
                    if (lengthBytes == 0) {
                        arg.str.clear();
                        arg.has_str = true;  // an empty counted string is a real value
                        break;
                    }
                    size_t chars = kind == ArgKind::CountedWideString
                        ? lengthBytes / sizeof(wchar_t)
                        : lengthBytes;
                    if (chars > opt.max_string) {
                        chars = opt.max_string;
                    }
                    auto s = kind == ArgKind::CountedWideString
                        ? readWideChars(src, bufferPtr, chars, &arg.str_truncated)
                        : readAnsiChars(src, bufferPtr, chars, &arg.str_truncated);
                    if (s) {
                        arg.str = std::move(*s);
                        arg.has_str = true;
                    }
                    break;
                }
                case ArgKind::Guid: {
                    uint8_t g[16] = {};
                    if (readGuest(src, ptr, g, sizeof(g))) {
                        arg.str = formatGuid(g);
                        arg.has_str = true;
                    }
                    break;
                }
                case ArgKind::AnsiBuffer:
                case ArgKind::WideBuffer:
                case ArgKind::ByteBuffer:
                    captureBuffer(src, opt, kind, ptr, byteCount, arg);
                    break;
                default:
                    break;
            }
        }

        // Some parameters are pointers whose pointee the metadata can't pin down:
        // the raw UInt16*/UIntPtr* that RPC uses for RPC_WSTR, and parameters no
        // source could classify at all. For those the guess-if-it-looks-like-text
        // heuristic is still the best information available.
        //
        // ArgKind::Pointer is deliberately not in that list. A prototype that says
        // `void*` is not missing information -- it is stating that the pointee has no
        // type, and guessing over it produced 33,526 strings in one trace, almost all
        // of them from memset's uninitialised destination and the block RtlFreeHeap
        // is releasing. Neither is a string; both were text the caller had finished
        // with. Explicit typing has to beat guesswork now that most calls have a
        // prototype, which was not true when this heuristic was written.
        bool mayHoldUntypedString(ArgKind kind) {
            return kind == ArgKind::Unknown || kind == ArgKind::PtrToInt;
        }

        void tryUntypedString(MemorySource const& src, DecodedArg& arg) {
            if (arg.has_str || !mayHoldUntypedString(arg.kind)) {
                return;
            }
            if (auto s = tryReadString(src, arg.raw, &arg.str_truncated)) {
                arg.str = std::move(*s);
                arg.has_str = true;
                return;
            }
            // A T** out-parameter: the string lives one more hop away.
            if (arg.has_deref) {
                if (auto s = tryReadString(src, arg.deref, &arg.str_truncated)) {
                    arg.str = std::move(*s);
                    arg.has_str = true;
                }
            }
        }

        bool needsDeref(ArgKind kind) {
            switch (kind) {
                case ArgKind::AnsiString:
                case ArgKind::WideString:
                case ArgKind::PtrToInt:
                case ArgKind::PtrToAnsiString:
                case ArgKind::PtrToWideString:
                case ArgKind::CountedAnsiString:
                case ArgKind::CountedWideString:
                case ArgKind::Guid:
                case ArgKind::AnsiBuffer:
                case ArgKind::WideBuffer:
                case ArgKind::ByteBuffer:
                    return true;
                default:
                    return false;
            }
        }

    }  // namespace

    bool x86StackLayout(const win32meta::FuncSig& sig, std::vector<uint16_t>& offsets) {
        offsets.clear();
        if (sig.paramCount > kMaxParams) {
            return false;
        }
        uint16_t computed[kMaxParams] = {};
        if (!computeStackOffsets(sig, computed)) {
            return false;
        }
        offsets.assign(computed, computed + sig.paramCount);
        return true;
    }

    bool decodeArgs(const win32meta::FuncSig& sig,
                    const CallFrame& frame,
                    const DecodeOptions& opt,
                    std::vector<DecodedArg>& out,
                    std::vector<PendingOut>& deferred) {
        if ((frame.arch == GuestArch::X64 && frame.x64 == nullptr)
            || (frame.arch == GuestArch::X86 && frame.x86 == nullptr)) {
            return false;
        }

        // Only the x86 path needs the per-parameter offset table, so only it is bound
        // by the table's size. An x64 signature is addressed by slot index and needs
        // no such array, and declining it here would send calls to the heuristic that
        // decode perfectly well today.
        uint16_t x86Offsets[kMaxParams] = {};
        if (frame.arch == GuestArch::X86
            && (sig.paramCount > kMaxParams || !computeStackOffsets(sig, x86Offsets))) {
            return false;
        }

        const uint16_t pointerSize = frame.pointerSize();
        MemorySource const src{ frame.thread };

        out.clear();
        out.resize(sig.paramCount);

        // Pass 1: capture every raw slot first. A buffer's length can live in a
        // parameter that comes *after* it (ReadFile's lpBuffer refers forward to
        // nNumberOfBytesToRead), so no dereferencing until all the scalars are in.
        for (uint8_t i = 0; i < sig.paramCount; ++i) {
            const win32meta::ParamSig& p = sig.params[i];
            DecodedArg& arg = out[i];
            arg.name = p.name;
            arg.type = p.type;
            arg.kind = p.kind;
            arg.enum_index = p.enumIndex;
            arg.is_out = p.isOut();

            bool ok = false;
            arg.raw = fetchArg(frame, sig, i, x86Offsets, ok);
            if (!ok) {
                // Stack slot we couldn't read: leave it zero rather than invent one.
                arg.raw = 0;
            }
            // A 32-bit guest's pointers and handles are 4 bytes; anything above that
            // in the word we read is not part of the value.
            if (pointerSize == 4 && isPointerKind(p.kind)) {
                arg.raw &= 0xFFFFFFFFull;
            }
            if (p.isFloat()) {
                arg.fval = floatValue(p, arg.raw);
                arg.has_fval = true;
            }
        }

        // Pass 2: dereference. Scalars and handles are deliberately untouched --
        // that alone removes most of the bogus String features the old heuristic
        // produced from flag values that happened to look like addresses.
        for (uint8_t i = 0; i < sig.paramCount; ++i) {
            const win32meta::ParamSig& p = sig.params[i];
            DecodedArg& arg = out[i];
            if (!needsDeref(p.kind)) {
                tryUntypedString(src, arg);
                continue;
            }

            uint64_t byteCount = isBufferKind(p.kind) ? resolveByteCount(p, out) : 0;

            // [In] contents are already valid here. [In,Out] gets read twice: once
            // now for what the caller passed, then again at the return.
            if (p.isIn()) {
                dereference(src, opt, p.kind, arg.raw, p.pointeeSize, pointerSize, byteCount, arg);
                tryUntypedString(src, arg);
            }
            if (p.isOut() && arg.raw >= kMinDerefAddr) {
                PendingOut pending;
                pending.param_index = i;
                pending.kind = p.kind;
                pending.ptr = arg.raw;
                pending.pointee_size = p.pointeeSize;
                pending.aux_kind = p.auxKind;
                pending.aux_value = p.auxValue;
                pending.in_cap = byteCount;
                deferred.push_back(pending);
            }
        }
        return true;
    }

    void resolvePendingOuts(const std::vector<PendingOut>& pending,
                            const CallFrame& frame,
                            const DecodeOptions& opt,
                            std::vector<DecodedArg>& args) {
        const uint16_t pointerSize = frame.pointerSize();
        MemorySource const src{ frame.thread };

        // Scalars first: a buffer's real length is usually itself an [Out] scalar
        // (ReadFile's lpNumberOfBytesRead), so it has to be resolved before the
        // buffer that depends on it.
        for (const PendingOut& po : pending) {
            if (po.param_index >= args.size() || isBufferKind(po.kind)) {
                continue;
            }
            DecodedArg& arg = args[po.param_index];
            DecodedArg fresh;
            dereference(src, opt, po.kind, po.ptr, po.pointee_size, pointerSize, 0, fresh);
            if (fresh.has_deref || fresh.has_str) {
                fresh.name = arg.name;
                fresh.type = arg.type;
                fresh.kind = arg.kind;
                fresh.enum_index = arg.enum_index;
                fresh.raw = arg.raw;
                fresh.is_out = true;
                fresh.from_return = true;
                arg = std::move(fresh);
            }
            tryUntypedString(src, arg);
        }

        for (const PendingOut& po : pending) {
            if (po.param_index >= args.size() || !isBufferKind(po.kind)) {
                continue;
            }
            DecodedArg& arg = args[po.param_index];

            // Prefer the length the callee reported; fall back to what the caller
            // offered, and never exceed it.
            win32meta::ParamSig probe;
            probe.auxKind = po.aux_kind;
            probe.auxValue = po.aux_value;
            probe.pointeeSize = po.pointee_size;
            uint64_t byteCount = resolveByteCount(probe, args);
            if (byteCount == 0) {
                byteCount = po.in_cap;
            } else if (po.in_cap != 0 && byteCount > po.in_cap) {
                byteCount = po.in_cap;
            }
            if (byteCount == 0) {
                continue;
            }

            DecodedArg fresh;
            captureBuffer(src, opt, po.kind, po.ptr, byteCount, fresh);
            if (!fresh.bytes.empty() || fresh.has_str) {
                arg.bytes = std::move(fresh.bytes);
                arg.str = std::move(fresh.str);
                arg.has_str = fresh.has_str;
                arg.str_truncated = fresh.str_truncated;
                arg.from_return = true;
            }
        }
    }

    bool recoverString(MemorySource const& src, const DecodeOptions& opt, DecodedArg& arg,
                       bool accept_truncated) {
        if (!isPlainStringKind(arg.kind) || arg.has_str) {
            return false;
        }
        bool truncated = false;
        auto s = arg.kind == ArgKind::AnsiString
                     ? readAnsiString(src, arg.raw, opt.max_string, &truncated)
                     : readWideString(src, arg.raw, opt.max_string, &truncated);
        if (!s || s->empty() || (truncated && !accept_truncated)) {
            return false;
        }
        arg.str = std::move(*s);
        arg.has_str = true;
        arg.str_truncated = truncated;
        return true;
    }

    std::vector<ArgValue> toCapaArgs(const std::vector<DecodedArg>& args) {
        std::vector<ArgValue> out;
        out.reserve(args.size());
        for (const DecodedArg& a : args) {
            // A string we know is incomplete must not be matched against. The
            // truncation is a property of what the trace recorded, not of the
            // program: `api-ms-win-e` is a cut-off `api-ms-win-core-...` module name,
            // and the fragment satisfies a rule alternation that the whole name does
            // not. Matching a prefix as though it were the value is matching an
            // artifact of the recording.
            //
            // The string is not lost -- it stays in `params`, where a reader gets it
            // with the truncation marked. This withholds only strings positively
            // identified as incomplete and judges nothing about their content.
            if (a.has_str && !a.str.empty() && !a.str_truncated) {
                out.push_back(a.str);
            } else {
                out.push_back(static_cast<int64_t>(a.raw));
            }
        }
        return out;
    }

}  // namespace ttdcapa
