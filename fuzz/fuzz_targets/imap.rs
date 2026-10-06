//! IMAP literals, refusal decisions, raw lines, and strict wire values.
#![no_main]

use fictionet::stdlib::codec::{Decode, Step, Wire, contract, test_support::decode_all};
use fictionet::stdlib::imap::{
    Command, Commands, DecodeError, Error, Input, MAX_HELD, MAX_LINE, MAX_LITERAL, MAX_TEXT,
    Response, Responses, Value,
};
use libfuzzer_sys::fuzz_target;

struct Refusals<'a> {
    commands: Commands,
    choices: &'a [u8],
    at: usize,
    refuse: bool,
}
impl Decode for Refusals<'_> {
    type Item = Result<Input, Error>;
    type Error = DecodeError;
    const NAME: &'static str = "IMAP refusal world";
    fn capacity(&self) -> usize {
        self.commands.capacity()
    }
    fn held(&self) -> usize {
        self.commands.held()
    }
    fn decode(&mut self, bytes: &[u8], eof: bool) -> Result<Step<Self::Item>, DecodeError> {
        if core::mem::take(&mut self.refuse) {
            assert!(self.commands.refuse_literal());
            assert!(!self.commands.refuse_literal());
        }
        let step = self.commands.decode(bytes, eof)?;
        if let Step::Item(item, _) = &step {
            let choice = self.choices.get(self.at % self.choices.len().max(1));
            self.refuse =
                matches!(item, Ok(Input::Continue { .. })) && choice.is_some_and(|b| b & 1 == 1);
            self.at = self.at.saturating_add(1);
        }
        Ok(step)
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Commands::new, data, 2 * MAX_LINE);
    contract::check_decode_with_alloc_limit(Responses::new, data, 2 * MAX_LINE);
    contract::check_decode_with_held_limit(Commands::new, data, MAX_HELD);
    contract::check_decode_with_held_limit(Responses::new, data, MAX_HELD);
    let raw = || {
        let mut commands = Commands::new();
        commands.expect_line().unwrap();
        commands
    };
    contract::check_decode_with_alloc_limit(raw, data, 2 * MAX_LINE);
    let choices = data.get(..8).unwrap_or(data);
    contract::check_decode_with_alloc_limit(
        || Refusals {
            commands: Commands::new(),
            choices,
            at: 0,
            refuse: false,
        },
        data,
        2 * MAX_LINE,
    );
    contract::check_wire::<Command>(data);
    contract::check_wire::<Response>(data);
    for item in decode_all(Commands::new, data).0 {
        if let Ok(Input::Command(command)) = item {
            let bytes = command.to_bytes().unwrap();
            contract::check_wire::<Command>(&bytes);
            let offsets = Command::continuation_offsets(&bytes).unwrap();
            assert!(offsets.windows(2).all(|w| w[0] < w[1]));
            assert!(offsets.iter().all(|&at| at <= bytes.len()));
        }
    }
    for response in decode_all(Responses::new, data).0.into_iter().flatten() {
        contract::check_wire::<Response>(&response.to_bytes().unwrap());
    }
    let text = String::from_utf8_lossy(data.get(..MAX_TEXT + 1).unwrap_or(data));
    let payload = data.get(..MAX_LITERAL + 1).unwrap_or(data);
    let non_sync = data.first().is_some_and(|b| b & 1 == 1);
    for value in [
        Value::atom(&text),
        Value::string(payload),
        Value::Literal {
            data: payload.to_vec(),
            non_sync,
        },
        Value::Binary {
            data: payload.to_vec(),
            non_sync,
        },
    ] {
        contract::check_wire_value(&Command::new("a", "APPEND", vec![value.clone()]));
        contract::check_wire_value(&Response::Data(vec![value]));
    }
    contract::check_wire_value(&Command::new(&text, &text, vec![]));
    contract::check_wire_value(&Response::greeting(&text));
    contract::check_wire_value(&Response::continue_req(&text));
});
