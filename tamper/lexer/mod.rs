#[derive(Clone, Copy, Debug)]
pub enum PatternToken {
    UnknownVariable,
    KnownVariable(u8),
}

const HEX_A: u8 = b'A';
const HEX_B: u8 = b'B';
const HEX_C: u8 = b'C';
const HEX_D: u8 = b'D';
const HEX_E: u8 = b'E';
const HEX_F: u8 = b'F';

const INT_0: u8 = b'0';
const INT_1: u8 = b'1';
const INT_2: u8 = b'2';
const INT_3: u8 = b'3';
const INT_4: u8 = b'4';
const INT_5: u8 = b'5';
const INT_6: u8 = b'6';
const INT_7: u8 = b'7';
const INT_8: u8 = b'8';
const INT_9: u8 = b'9';

const UNKNOWN_VAR: u8 = b'x';

#[derive(Debug, PartialEq)]
enum LexerExpectation {
    NextIsHex,
    NextIsSeparate,
}

pub fn pattern_lexer(pattern: String) -> Vec<PatternToken> {
    let mut stream = Vec::<PatternToken>::new();

    let mut expectation: LexerExpectation = LexerExpectation::NextIsSeparate;

    let accessor: Vec<_> = pattern.as_bytes().to_vec();

    if accessor.len() < 2 {
        panic!("A pattern cannot have a length less than 2. You can't have a pattern that always resolves to 'true', since it defeats the point of patterns. Use fake packet injections instead.");
    }

    for index in 0..accessor.len() {
        let byte = accessor[index];

        match byte {
            HEX_A
            | HEX_B
            | HEX_C
            | HEX_D
            | HEX_E
            | HEX_F
            | INT_0
            | INT_1
            | INT_2
            | INT_3
            | INT_4
            | INT_5
            | INT_6
            | INT_7
            | INT_8
            | INT_9 => {
                if expectation == LexerExpectation::NextIsHex {
                    expectation = LexerExpectation::NextIsSeparate;
                    if index == 0 {
                        panic!("Failed to compile pattern: Can't have a complete hex from one byte");
                    }

                    let previous = accessor[index - 1];

                    /*
                     * Borrowck will basically do inappropriate things to the person who
                     * replaces String with std::str here
                     */

                    let src = String::from_utf8(vec![previous, byte]).expect("Failed to compile pattern: Wrong hex sequence");

                    let int = u8::from_str_radix(&src, 16).expect("Failed to compile pattern: Not a valid hex");

                    stream.push(PatternToken::KnownVariable(int));
                } else {
                    expectation = LexerExpectation::NextIsHex;
                }
            }

            UNKNOWN_VAR => {
                if expectation == LexerExpectation::NextIsHex {
                    panic!("Failed to compile pattern {pattern}. Unexpected token UNKNOWN_VAR while expecting {expectation:?}");
                }

                stream.push(PatternToken::UnknownVariable);

                expectation = LexerExpectation::NextIsSeparate;
            }

            token => panic!("Failed to compile pattern {pattern}. Got an unknown token {token}, which I don't know how to lex!"),
        }
    }

    if expectation != LexerExpectation::NextIsSeparate {
        panic!(
            "Failed to compile pattern {pattern}. The pattern wasn't fully compiled. Recheck whether the hex sequences are complete."
        );
    }

    stream
}
