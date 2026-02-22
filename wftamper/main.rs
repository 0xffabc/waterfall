use crate::lexer::PatternToken;

pub mod lexer;
pub mod service;

pub fn edit_packet_by_pattern(
    pattern: Vec<PatternToken>,
    replacement: Vec<PatternToken>,
    packet: &mut Vec<u8>,
) {
    let mut index = 0;

    loop {
        if index + pattern.len() > packet.len() {
            break;
        }

        let mut match_found = true;

        for pattern_index in 0..pattern.len() {
            match pattern[pattern_index] {
                PatternToken::KnownVariable(byte) => {
                    if byte != packet[index + pattern_index] {
                        match_found = false;
                        break;
                    }
                }

                PatternToken::UnknownVariable => continue,
            }
        }

        if match_found {
            if pattern.len() == replacement.len() {
                for replacement_index in 0..replacement.len() {
                    match replacement[replacement_index] {
                        PatternToken::KnownVariable(byte) => {
                            if index + replacement_index < packet.len() {
                                packet[index + replacement_index] = byte;
                            }
                        }

                        PatternToken::UnknownVariable => {}
                    }
                }

                index += pattern.len();
            } else if pattern.len() < replacement.len() {
                let extra = replacement.len() - pattern.len();
                let pos = index + pattern.len();

                /* We have to extend the vec with zero bytes and
                 * overlap everything on it afterwards
                 */
                packet.splice(pos..pos, vec![0; extra]);

                for replacement_index in 0..replacement.len() {
                    match replacement[replacement_index] {
                        PatternToken::KnownVariable(byte) => {
                            if index + replacement_index < packet.len() {
                                packet[index + replacement_index] = byte;
                            }
                        }

                        PatternToken::UnknownVariable => {}
                    }
                }

                index += replacement.len();
            } else {
                /* replacement is less than pattern */
                for replacement_index in 0..replacement.len() {
                    match replacement[replacement_index] {
                        PatternToken::KnownVariable(byte) => {
                            if index + replacement_index < packet.len() {
                                packet[index + replacement_index] = byte;
                            }
                        }

                        PatternToken::UnknownVariable => {}
                    }
                }

                packet.drain((index + replacement.len())..(index + pattern.len()));

                index += replacement.len();
            }
        } else {
            index += 1;
        }
    }
}

pub fn edit_http(mut data: Vec<u8>) -> Vec<u8> {
    let conf = wfconfig::parse_args();

    for iter in 0..data.len() {
        // Scan for HTTP

        if iter + 4 < data.len()
            && data[iter] == 72
            && data[iter + 1] == 111
            && data[iter + 2] == 115
            && data[iter + 3] == 116
            && data[iter + 4] == 58
        {
            if conf.http_options.http_host_cmix {
                data[iter + 1] = 79;
                data[iter + 3] = 84;
            }

            if conf.http_options.http_host_rmspace && data[iter + 5] == 32 {
                data.remove(iter + 5);
            }

            if conf.http_options.http_host_space {
                data.insert(iter + 5, 32);
            }

            if conf.http_options.http_domain_cmix {
                let b = std::str::from_utf8(&[data[iter + 6]])
                    .expect("HOST detected but domain is wrong")
                    .to_uppercase();

                data[iter + 6] = b.as_bytes()[0];
            }
        }
    }

    data
}

pub fn as_record(data: Vec<u8>) -> Vec<u8> {
    let data_length: [u8; 2] = (data.len() as u16).to_be_bytes();
    let mut record: Vec<u8> = vec![0x16u8, 0x03u8, 0x01u8];

    record.extend(data_length);
    record.extend(data);

    record
}

pub fn edit_tls(mut data: Vec<u8>, index: usize) -> Vec<u8> {
    if data[0] == 0x16 && data[1] == 0x03 && data[2] == 0x01 {
        let payload = data.split_off(5);
        let (first_part, second_part) = payload.split_at(index);

        let record1 = as_record(first_part.to_vec());
        let record2 = as_record(second_part.to_vec());

        let mut result = record1;
        result.extend(record2);

        return result;
    }

    data
}
