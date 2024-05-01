use std::process::ExitCode;

use caps::errors::CapsError;
use caps::CapSet;
use caps::Capability;

fn main() -> Result<ExitCode, CapsError> {
    // bounding set
    if caps::has_cap(None, CapSet::Effective, Capability::CAP_SETPCAP)?
        && caps::has_cap(None, CapSet::Bounding, Capability::CAP_SYS_PTRACE)?
    {
        return Ok(ExitCode::FAILURE);
    }
    // other sets
    for set in [
        CapSet::Permitted,
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
