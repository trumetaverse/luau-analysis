use std::error::Error as StdErr;
use std::{collections::HashMap, rc::Rc};


#[derive(Eq, Hash, PartialEq)]
pub enum CommandCode {
    None,
    ExitInteractive,
}

#[derive(Eq, Hash, PartialEq)]
pub enum CommandResults {
    None,
    ExitInteractive
}

pub struct ExecutionState {
    pub state: HashMap<String, String>
}

pub struct CommandHandler {
    pub commands: Rc<HashMap<CommandCode, Box<dyn Command>>>,
    pub state: HashMap<String, String>,
}
const EXIT: &str = "exit";

impl CommandHandler {

    pub fn should_quit(&self) -> bool {
        return self.state.contains_key(&EXIT.to_string()) && self.get_state(EXIT.to_string()).unwrap() == "true";
    }

    pub fn get_state(&self, key: String) -> Option<String>{
        if self.state.contains_key(&key) {
            return self.state.get(&key).cloned();
        }
        return None;
    }

    pub fn set_state(&mut self, key : String, value: String) -> bool {
        self.state.insert(key, value);
        return true;
    }
    pub fn tokenize_input(&self, input_string: String) -> Vec<String> {
        let res: Vec<String> = input_string.split(" ").map(|s| s.to_string()).collect();
        return res;
    }

    pub fn command_dispatch(&mut self, input_vec: Vec<String>) -> Result<CommandResults, Box<dyn StdErr>> {
        let hm = Rc::clone(&self.commands);
        for (_, cmd) in hm.iter_mut() {
            if (*cmd).check_args(self, &input_vec) {
                return (*cmd).execute( &mut self, &input_vec);
            }
        }
        return Ok(CommandResults::None);
    }

    pub fn register_command(&mut self, cmd: Box<dyn Command>) -> Result<CommandCode, Box<dyn StdErr>> {
        if self.commands.contains_key(&cmd.get_code()) {
            // TODO throw an error
            return Ok(CommandCode::None);
        }
        let cmd_code = cmd.get_code();
        self.commands.insert(cmd.get_code(), cmd);
        return Ok(cmd_code);
    }

}

pub trait Command {
    fn execute(&self, handler: &mut CommandHandler, args: &Vec<String>) -> Result<CommandResults, Box<dyn StdErr>>;
    fn check_args(&self, handler: &mut CommandHandler, args: &Vec<String>) -> bool;
    fn get_code(&self) -> CommandCode;
}