pub struct Whitelist();

impl Whitelist {
    pub fn check_whitelist(
        config: &Option<Vec<String>>,
        sni_data: &(u32, u32),
        data: &[u8],
    ) -> bool {
        if let Some(whitelist_sni_list) = config {
            if sni_data != &(0, 0) {
                let start = sni_data.0 as usize;
                let end = sni_data.1 as usize;

                if data.len() <= end {
                    return false;
                }

                let sni_slice = &data[start..end];

                let sni_string = String::from_utf8_lossy(sni_slice).to_string();

                debug!("Visiting SNI {sni_string}");

                if whitelist_sni_list
                    .iter()
                    .position(|r| sni_string.contains(r))
                    .is_none()
                {
                    return false;
                }
            }

            if sni_data == &(0, 0) {
                return false;
            }
        }

        return true;
    }
}
