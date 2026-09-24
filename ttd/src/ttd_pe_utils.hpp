#pragma once

#include "ttdutils.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include <TTD/IdnaBasicTypes.h>
#include <TTD/IReplayEngineStl.h>

namespace ttdcapa {
	// Read `size` bytes of guest virtual memory at `addr` into `dst`. Returns the number of bytes actually available/read (may be < size).
	using GuestReader = std::function<size_t(TTD::GuestAddress addr, void* dst, size_t size)>;

	// What a mapped image says it is. Neither field is in the TTD module list, and a WoW64
	// trace holds both bitnesses at once, so both have to come from the mapped headers.
	// `machine` is what separates x64 from ARM64: they share the PE32+ magic, so the
	// optional header alone cannot tell them apart.
	struct ModuleFormat {
		bool is64 = true;
		uint16_t machine = 0;  // IMAGE_FILE_MACHINE_*
	};

	// Read the image format of the PE mapped at `base`. Returns false if `base` is not a
	// readable PE image at this position.
	bool getModuleFormat(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, ModuleFormat& out);

	// "x86", "x64", "arm64", "arm", or "unknown". Derived from `machine` where it is one we
	// recognise and from the bitness otherwise, so an image built for something exotic still
	// gets an answer of the right width.
	const char* archName(const ModuleFormat& format);

	// Parse the export directory of the PE image mapped at `base`. Appends one entry
	// per named export (forwarders are skipped). Returns false if `base` is not a
	// readable PE32 or PE32+ image at this position.
	//
	// `is64Bit`, when given, receives the image's bitness. The bitness of the module
	// owning a call target is what selects the calling convention used to decode that
	// call's arguments.
	bool getModuleExports(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress,
		std::vector<std::pair<uint64_t, std::string>>& out, bool* is64Bit = nullptr);

	// The end of the function that starts at `entry`, from the image's x64 function table
	// (.pdata): the one place a PE records how long a function is. Only the primary chunk --
	// a function split into cold chunks ends where its first chunk does. Returns false for a
	// 32-bit image, which has no such table, and for an `entry` the table does not list.
	bool getFunctionEnd(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, uint64_t entry, uint64_t& end);

	// Parse the import directory of the PE image mapped at `base`.
	bool getModuleImports(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, std::vector<ImportRecord>& out);

	// Parse the section table of the PE image mapped at `base`.
	bool getModuleSections(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, std::vector<SectionRecord>& out);

	// Recover ASCII and UTF-16LE strings (length >= min_len) from the image's mapped
	// sections. Caps output at `max_strings` to keep the report bounded.
	bool getModuleStrings(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, std::vector<std::string>& out, size_t minLength = 5, size_t maxStrings = 2000);

	// Strip a path/extension from a module name: "C:\\WINDOWS\\System32\\kernel32.dll" -> "kernel32".
	std::string getModuleBaseName(const std::wstring& full);
}
