mod types;
use crate::types::*;
mod functions;
use crate::functions::*;
mod build_upgrade;
use crate::build_upgrade::{build_upgrade, UpgradeArgs};
mod submit_referendum;
use crate::submit_referendum::{submit_referendum, ReferendumArgs};
mod scaffold_tests;
use crate::scaffold_tests::{scaffold_tests, ScaffoldTestsArgs};
mod chopsticks;
use clap::Parser as ClapParser;

#[cfg(test)]
mod tests;

/// Utilities for submitting OpenGov referenda and constructing tedious calls.
#[derive(Debug, ClapParser)]
enum Command {
	BuildUpgrade(UpgradeArgs),
	SubmitReferendum(ReferendumArgs),
	ScaffoldTests(ScaffoldTestsArgs),
}

#[tokio::main]
async fn main() {
	let args = Command::parse();
	match args {
		Command::BuildUpgrade(prefs) => build_upgrade(prefs).await,
		Command::SubmitReferendum(prefs) => submit_referendum(prefs).await,
		Command::ScaffoldTests(prefs) => scaffold_tests(prefs).await,
	}
}
