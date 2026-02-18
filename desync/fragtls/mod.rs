use crate::core::strategy::Strategy;

pub struct FragTls;

impl FragTls {
    pub fn execute_strategy(
        current_data: &mut Vec<u8>,
        strategy: Strategy,
        sni_data: &'_ (u32, u32),
    ) {
        if strategy.add_sni {
            let (sni_start, _sni_end) = &sni_data;

            *current_data = crate::tamper::edit_tls(
                current_data.to_vec(),
                (strategy.base_index + (*sni_start as i64))
                    .try_into()
                    .unwrap(),
            );
        } else {
            *current_data = crate::tamper::edit_tls(
                current_data.to_vec(),
                strategy.base_index.try_into().unwrap(),
            );
        }
    }
}
