#ifndef TTDCAPA_STATUS_HPP
#define TTDCAPA_STATUS_HPP

// The outcome of one analysis pass, shared by all three of them (call sweep, code scan,
// execute-hit trace) so the CLI and the C API in include/ttdcapa.h can report failures the
// same way. The values are mirrored one-for-one by ttdcapa_status; keep them in step.
namespace ttdcapa {
    enum class Status {
        Ok = 0,
        InvalidArgument,   // a required path or option was missing or nonsensical
        EngineFailed,      // the TTD replay engine could not be created, or the trace not opened
        UnsupportedArch,   // the guest is neither x86 nor x64
        BadInput,          // an input file exists but could not be parsed
        IoFailed,          // an output file could not be written
        Cancelled,         // the caller's cancellation predicate asked us to stop
        Internal,          // an unexpected exception escaped a pass
    };

    inline char const* statusMessage(Status status) {
        switch (status) {
            case Status::Ok:              return "ok";
            case Status::InvalidArgument: return "invalid argument";
            case Status::EngineFailed:    return "the TTD replay engine could not open the trace";
            case Status::UnsupportedArch: return "only x86 and x64 traces are supported in this version";
            case Status::BadInput:        return "an input file could not be parsed";
            case Status::IoFailed:        return "an output file could not be written";
            case Status::Cancelled:       return "cancelled by the caller";
            case Status::Internal:        return "internal error";
        }
        return "unknown error";
    }

    // Process exit code for a status, so the command-line tool keeps reporting the same
    // codes it always has (2 for an unsupported trace, 3 for anything else that failed).
    inline int exitCode(Status status) {
        switch (status) {
            case Status::Ok:              return 0;
            case Status::UnsupportedArch: return 2;
            default:                      return 3;
        }
    }
}

#endif
