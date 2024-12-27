
mod utils {
  pub fn aob_scan(target: Vec<u8>, source: Vec<u8>) -> usize {
    for (position, window) in source.windows(target.len()).enumerate() {
      if window == target {
        return position;
      }
    }

    return usize::MIN;
  }

  pub fn slice_packet(source: Vec<u8>, index: u8) -> Vec<Vec<u8>> {
    let mut current_index: u8 = 0;

    let mut alpha: Vec<u8> = Vec::new();
    let mut beta: Vec<u8> = Vec::new();

    for byte in source {
      if current_index >= index {
        alpha.push(byte);
      } else {
        beta.push(byte);
      }

      current_index += 1;
    }

    vec![beta, alpha]
  }

  // This is the laziest solution ever possible, but it works at least.
  // Assuming SNI size is less than u8
  pub fn parse_sni(source: Vec<u8>) -> String {
    let mut sni: String = String::from("");

    'label: for iter in 0..source.len() {
      if iter + 8 > source.len() {
        break 'label;
      }

      if source[iter] != 0 || source[iter + 1] != 0 {
        continue;
      }

      if source[iter + 3] - source[iter + 5] != 2 {
        continue;
      }

      let hostname_size: usize = (((source[iter + 4] as u32) << 8) as u32 | (source[iter + 5] as u32)) as usize;
      println!("{:?}", hostname_size);
      // Save the SNI and return from loop

      for jter in iter..(iter + hostname_size) {
        if jter > source.len() {
          break;
        }

        match std::str::from_utf8(&[source[jter]]) {
          Ok(ch) => sni += &ch,
          Err(_) => continue 'label
        }
      }

      return sni;
    }

    sni
  }
}

#[cfg(test)]

mod tests {
  use super::*;

  #[test]

  fn test_aob_scan_start() {
    let pattern_start: usize = utils::aob_scan(vec![0, 5], vec![0, 5, 6, 2]);

    assert_eq!(0 as usize, pattern_start);
  }

  #[test]

  fn test_aob_scan_middle() {
    assert_eq!(3 as usize, 
      utils::aob_scan(vec![16, 43], vec![78, 34, 22, 16, 43, 27]));
  }

  #[test]

  fn test_aob_scan_end() {
    assert_eq!(5 as usize,
      utils::aob_scan(vec![8, 1], vec![0, 0, 0, 0, 0, 8, 1]));
  }

  #[test]

  fn test_slice_packet() {
    let packet: Vec<u8> = vec![56, 78, 32];

    let split_packet: Vec<Vec<u8>> = utils::slice_packet(packet, 1);
  
    assert_eq!(vec![56], split_packet[0]);
    assert_eq!(vec![78, 32], split_packet[1]);
  }

  #[test]

  fn test_sni_parser() {
    let packet: Vec<u8> = vec![0, 0, 0, 12, 0, 10, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 0, 0];

    assert_eq!(utils::parse_sni(packet), "google.com".to_owned());
  }
}
