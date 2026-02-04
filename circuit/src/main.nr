use dep::poseidon::poseidon;

global MERKLE_DEPTH: u32 = 3; // 3 for demo

struct Note {
    amount: Field,  // Purpose Bound Money amount
    pbm_token_id: Field,
    owner: Field,   // Hash(Pubkey) of Sender (for old) or Receiver (for new)
    donor: Field,   // Hash(Pubkey) of the Original Donor (Fixed)
    salt: Field,
}

fn note_hash(note: Note) -> Field {
    let inputs = [
        note.amount,
        note.pbm_token_id,
        note.owner,
        note.donor,
        note.salt,
    ];
    poseidon::bn254::hash_5(inputs)
}

fn compute_merkle_proof(
    leaf: Field,
    index: u32,
    path: [Field; MERKLE_DEPTH],
) -> Field {
    let mut current_hash = leaf;
    let mut current_index = index;

    for i in 0..MERKLE_DEPTH {
        let sibling_hash = path[i];
        let is_right = current_index as u32 % 2;
        if is_right == 0 {
            current_hash = poseidon::bn254::hash_2([current_hash, sibling_hash]);
        } else {
            current_hash = poseidon::bn254::hash_2([sibling_hash, current_hash]);
        }
        current_index = current_index / 2;
    }

    current_hash
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
