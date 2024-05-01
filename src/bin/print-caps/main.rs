use std::process::ExitCode;

use caps::errors::CapsError;
use caps::CapSet;

fn main() -> Result<ExitCode, CapsError> {
    for set in [
        CapSet::Permitted,
        CapSet::Effective,
        CapSet::Inheritable,
        CapSet::Ambient,
        CapSet::Bounding,
    ] {
        let capabilities = caps::read(None, set)?;
        let mut capabilities = capabilities
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>();
        capabilities.sort();
        println!("{:?}: {}", set, capabilities.join(" "));
    }
    Ok(ExitCode::SUCCESS)
}
