use caps::errors::CapsError;
use caps::CapSet;
use caps::Capability;
use std::process::ExitCode;

fn main() -> Result<ExitCode, CapsError> {
    for set in [
        CapSet::Bounding,
        CapSet::Effective,
        CapSet::Inheritable,
        CapSet::Ambient,
    ] {
        if caps::has_cap(None, set, Capability::CAP_SYS_PTRACE)? {
            return Ok(ExitCode::FAILURE);
        }
    }
    Ok(ExitCode::SUCCESS)
}
