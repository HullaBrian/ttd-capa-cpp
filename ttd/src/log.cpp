#include "log.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdio>
#include <iostream>
#include <streambuf>
#include <string>

namespace ttdcapa::log {
    namespace {
        Sink g_sink = nullptr;
        void* g_user = nullptr;
        bool g_verbose = false;

        // Messages carry their severity in the prefix the codebase has always used, so the
        // level can be recovered without touching a single call site.
        Level levelOf(std::string const& line) {
            size_t i = line.find_first_not_of(" \t");
            if (i == std::string::npos || i + 2 >= line.size()) return Level::Info;
            if (line.compare(i, 3, "[-]") == 0) return Level::Error;
            if (line.compare(i, 3, "[!]") == 0) return Level::Warn;
            return Level::Info;
        }

        // `debug` says which stream the line came from, not what it looks like: narration is
        // marked "[+]" like everything else, so only its origin distinguishes it.
        void emit(std::string& line, bool debug = false) {
            if (line.empty()) return;
            if (debug && !g_verbose) {
                line.clear();  // not produced at all, so no sink ever sees a level it may not know
                return;
            }
            if (line.back() == '\r') line.pop_back();  // tolerate CRLF from any source
            Level const level = debug ? Level::Debug : levelOf(line);
            if (g_sink != nullptr) {
                g_sink(g_user, level, line.c_str());
            } else {
                std::fputs(line.c_str(), stderr);
                std::fputc('\n', stderr);
            }
            line.clear();
        }

        std::string toUTF8(std::wstring const& ws) {
            if (ws.empty()) return {};
            int const need = ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()),
                                                   nullptr, 0, nullptr, nullptr);
            if (need <= 0) return {};
            std::string out(static_cast<size_t>(need), '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()),
                                  out.data(), need, nullptr, nullptr);
            return out;
        }

        // Accumulates characters until a newline, then hands the completed line to the sink.
        // Buffering by line (rather than per character) is what lets a sink be a plain
        // "here is a message" callback instead of a stream of fragments.
        class LineBuf : public std::streambuf {
        public:
            explicit LineBuf(bool debug = false) : debug_(debug) {}

        protected:
            int_type overflow(int_type c) override {
                if (traits_type::eq_int_type(c, traits_type::eof())) return traits_type::not_eof(c);
                char const ch = traits_type::to_char_type(c);
                if (ch == '\n') {
                    emit(pending_, debug_);
                } else {
                    pending_.push_back(ch);
                }
                return c;
            }

            std::streamsize xsputn(char const* s, std::streamsize n) override {
                for (std::streamsize i = 0; i < n; ++i) overflow(traits_type::to_int_type(s[i]));
                return n;
            }

            int sync() override {
                emit(pending_, debug_);
                return 0;
            }

        private:
            std::string pending_;
            bool debug_;
        };

        // Wide counterpart: guest strings (module paths and the like) are wchar_t, and the
        // sink contract is UTF-8, so conversion happens once per completed line.
        class WLineBuf : public std::wstreambuf {
        protected:
            int_type overflow(int_type c) override {
                if (traits_type::eq_int_type(c, traits_type::eof())) return traits_type::not_eof(c);
                wchar_t const ch = traits_type::to_char_type(c);
                if (ch == L'\n') {
                    std::string utf8 = toUTF8(pending_);
                    pending_.clear();
                    emit(utf8);
                } else {
                    pending_.push_back(ch);
                }
                return c;
            }

            std::streamsize xsputn(wchar_t const* s, std::streamsize n) override {
                for (std::streamsize i = 0; i < n; ++i) overflow(traits_type::to_int_type(s[i]));
                return n;
            }

            int sync() override {
                std::string utf8 = toUTF8(pending_);
                pending_.clear();
                emit(utf8);
                return 0;
            }

        private:
            std::wstring pending_;
        };

        LineBuf& narrowBuf() {
            static LineBuf buf;
            return buf;
        }

        LineBuf& debugBuf() {
            static LineBuf buf(true);
            return buf;
        }

        WLineBuf& wideBuf() {
            static WLineBuf buf;
            return buf;
        }
    }  // namespace

    void setSink(Sink sink, void* user) {
        flush();  // don't attribute the previous sink's half-written line to the new one
        g_sink = sink;
        g_user = user;
    }

    void setVerbose(bool enabled) {
        // Same reasoning as setSink: a partial line belongs to the verbosity it was written
        // under, not the one that replaces it.
        flush();
        g_verbose = enabled;
    }

    bool verbose() {
        return g_verbose;
    }

    std::ostream& err() {
        static std::ostream stream(&narrowBuf());
        return stream;
    }

    std::ostream& dbg() {
        static std::ostream stream(&debugBuf());
        return stream;
    }

    std::wostream& werr() {
        static std::wostream stream(&wideBuf());
        return stream;
    }

    void flush() {
        narrowBuf().pubsync();
        debugBuf().pubsync();
        wideBuf().pubsync();
    }

    ScopedSink::ScopedSink(Sink sink, void* user) : prevSink_(g_sink), prevUser_(g_user) {
        setSink(sink, user);
    }

    ScopedSink::~ScopedSink() {
        flush();
        setSink(prevSink_, prevUser_);
    }

    ScopedVerbosity::ScopedVerbosity(bool enabled) : previous_(g_verbose) {
        setVerbose(enabled);
    }

    ScopedVerbosity::~ScopedVerbosity() {
        setVerbose(previous_);
    }
}  // namespace ttdcapa::log
