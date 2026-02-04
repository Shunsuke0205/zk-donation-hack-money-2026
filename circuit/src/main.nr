use dep::poseidon::poseidon;

struct Note {
    amount: Field,  // Purpose Bound Money amount
    pbm_token_id: Field,
    owner: Field,   // Hash(Pubkey) of Sender (for old) or Receiver (for new)
    donor: Field,   // Hash(Pubkey) of the Original Donor (Fixed)
    salt: Field,
}

fn main(x: u64, y: pub u64) {
    assert(x != y);
}

#[test]
fn test_main() {
    main(1, 2);

    // Uncomment to make test fail
    // main(1, 1);
}
