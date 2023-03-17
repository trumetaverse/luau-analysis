use crate::handler::{CommandCode, CommandHandler, CommandResults, Command};
use std::error::Error as StdErr;

const EXIT_TOKENS: [&str; 2] = ["exit", "e"];

pub struct ExitCommand {}

impl Command for ExitCommand {
    fn execute(&self, handler: &mut CommandHandler, args: &Vec<String>) -> Result<CommandResults, Box<dyn StdErr>> {
        handler.set_state("exit".to_string(), "true".to_string());
        return Ok(CommandResults::ExitInteractive);
    }

    fn check_args(&self, handler: &mut CommandHandler, args: &Vec<String>) -> bool {
        if args.len() < 1 {
            return false;
        }
        let binding = args.get(0);
        let sub = binding.as_ref().unwrap();
        if sub.eq_ignore_ascii_case("exit") || sub.chars().nth(0).unwrap() == 'e' {
            return true;
        }
        return false;
    }

    fn get_code(&self) -> CommandCode {
        return CommandCode::ExitInteractive;
    }


}