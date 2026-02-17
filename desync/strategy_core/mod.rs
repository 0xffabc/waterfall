use crate::core::strategy::Strategy;

trait SplitPacket {
    fn get_split_packet(
        packet_buffer: &[u8],
        strategy: Strategy,
        sni_data: &(u32, u32),
    ) -> Vec<Vec<u8>>;
}

trait StrategyExecutor {
    fn execute_strategy(send_data: Vec<Vec<u8>>, current_data: &mut Vec<u8>);
}

trait StrategyConfig<T: From<String>> {
    fn to_readable() -> T;
    fn inject_config(conf: T);
}
