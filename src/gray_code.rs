//! Simple Gray code utilities

pub(crate) fn gray_code(n: usize) -> usize {
    n ^ n >> 1
}

#[cfg(test)]
mod tests {
    use crate::gray_code::*;

    #[test]
    fn test() {
        // Just trying to hit some corner cases
        assert_eq!(gray_code(0), 0b00000000);
        assert_eq!(gray_code(1), 0b00000001);
        assert_eq!(gray_code(2), 0b00000011);
        assert_eq!(gray_code(3), 0b00000010);
        assert_eq!(gray_code(5), 0b00000111);
        assert_eq!(gray_code(10), 0b00001111);
        assert_eq!(gray_code(11), 0b00001110);
        assert_eq!(gray_code(15), 0b00001000);
        assert_eq!(gray_code(16), 0b00011000);
        assert_eq!(gray_code((1 << 8) - 1), 128);
        assert_eq!(gray_code(1 << 8), 384);
        assert_eq!(gray_code((1 << 8) + 1), 385);
        assert_eq!(gray_code((1 << 16) - 1), 32_768);
        assert_eq!(gray_code(1 << 16), 98_304);
        assert_eq!(gray_code((1 << 16) + 1), 98_305);
        assert_eq!(gray_code((1 << 32) - 1), 2_147_483_648);
        assert_eq!(gray_code(1 << 32), 6_442_450_944);
        assert_eq!(gray_code((1 << 32) + 1), 6_442_450_945);
    }
}
