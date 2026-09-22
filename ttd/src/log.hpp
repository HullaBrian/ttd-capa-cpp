#ifndef TTDCAPA_LOG_HPP
#define TTDCAPA_LOG_HPP

#include <ostream>

// Progress diagnostics for the extractor's library code.
//
// Everything that used to go straight to std::cerr goes through here instead. The default
// sink *is* stderr, so the command-line tool behaves exactly as it always did; an embedding
// host (see include/ttdcapa.h) installs its own sink so a long replay's progress lands in
// that host's log rather than being scribbled onto its stderr.
//
// A library has no business owning the process's error stream, which is the whole reason
// this indirection exists.
namespace ttdcapa::log {
    // Debug is the library's running commentary -- which stage started, how long a replay took,
    // which export a breakpoint landed on. It is deliberately last: the first three are ordered
    // by severity and a host comparing against them must keep working, so the new value sits
    // past the end rather than in the middle.
    enum class Level { Info, Warn, Error, Debug };

    // Receives one complete line at a time: UTF-8, with the trailing newline stripped.
    using Sink = void (*)(void* user, Level level, char const* utf8Line);

    // Installs the sink used by subsequent output; nullptr restores the stderr default.
    // Not thread-safe against concurrent logging -- install it before starting an analysis.
    void setSink(Sink sink, void* user);

    // Whether Debug output is produced at all. Off by default, which is what makes this safe
    // for an embedding host: a caller that predates the level never receives one. The CLI turns
    // it on, so its output is unchanged.
    void setVerbose(bool enabled);
    bool verbose();

    // Line-buffered output streams, used exactly like std::cerr / std::wcerr. A line reaches
    // the sink once it is terminated by '\n'; a trailing partial line is delivered on flush.
    //
    // Levels are inferred from the "[-] " / "[!] " / "[+] " prefixes the codebase already
    // writes, so call sites need say nothing about severity.
    std::ostream& err();
    std::wostream& werr();

    // Narration. Everything written here is Level::Debug whatever marker it carries, and is
    // discarded entirely unless setVerbose(true) -- so a host's default log holds the passes'
    // findings and not their commentary.
    //
    // The stream, rather than a fourth "[~]" marker, is what makes a line Debug. That keeps the
    // three markers hosts already parse the only ones on the wire, and keeps the CLI's output
    // byte-for-byte what it was.
    //
    // Do not split one logical line across err() and dbg(): they buffer separately, so the two
    // halves would arrive as two messages. Where a line is assembled from fragments (see
    // writeReport, which finishes "[+] Generating JSON report..." with "DONE!") every fragment
    // belongs on the same stream, and anything of a different severity goes out as a line of
    // its own.
    std::ostream& dbg();

    // Pushes out any buffered partial line. Called at the end of each library entry point.
    void flush();

    // Installs a sink for the duration of a scope and restores the previous one after, so a
    // library entry point cannot leak its caller's sink into the next call.
    class ScopedSink {
    public:
        ScopedSink(Sink sink, void* user);
        ~ScopedSink();
        ScopedSink(ScopedSink const&) = delete;
        ScopedSink& operator=(ScopedSink const&) = delete;

    private:
        Sink prevSink_;
        void* prevUser_;
    };

    // The same discipline for verbosity: one pass asking for narration must not leave it on for
    // the next caller, who may well be a different host with a different appetite for it.
    class ScopedVerbosity {
    public:
        explicit ScopedVerbosity(bool enabled);
        ~ScopedVerbosity();
        ScopedVerbosity(ScopedVerbosity const&) = delete;
        ScopedVerbosity& operator=(ScopedVerbosity const&) = delete;

    private:
        bool previous_;
    };
}

#endif
