// All comments must be in English.

use dep::poseidon::poseidon;

global MERKLE_DEPTH: u32 = 3; // 3 for demo

struct Note {
    amount: u64,  // Purpose Bound Money amount
    pbm_token_id: u32,
    owner: Field,   // Hash(Pubkey) of Sender (for old) or Receiver (for new)
    donor: Field,   // Hash(Pubkey) of the Original Donor (Fixed)
    salt: Field,
}

fn note_hash(note: Note) -> Field {
    let inputs = [
        note.amount as Field,
        note.pbm_token_id as Field,
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
        let is_right = current_index % 2;
        if is_right == 0 {
            current_hash = poseidon::bn254::hash_2([current_hash, sibling_hash]);
        } else {
            current_hash = poseidon::bn254::hash_2([sibling_hash, current_hash]);
        }
        current_index = current_index / 2;
    }

    current_hash
}

fn verify_old_note(
    old_note: Note,
    pbm_token_id: u32,
    funder_public_point: std::embedded_curve_ops::EmbeddedCurvePoint,
    owner_private_key: std::embedded_curve_ops::EmbeddedCurveScalar,
    nullifier: Field,
    merkle_root: Field,
    merkle_index: u32,
    merkle_path: [Field; MERKLE_DEPTH],
    is_dummy: bool,
) {
    assert_eq(old_note.pbm_token_id, pbm_token_id, "PBM Token ID does not match");
    {
        let derived_funder_hash = poseidon::bn254::hash_2([
            funder_public_point.x,
            funder_public_point.y,
        ]);
        assert_eq(old_note.donor, derived_funder_hash, "Funder public key mismatch for old note");
    }
    {
        let derived_owner_public_point = std::embedded_curve_ops::fixed_base_scalar_mul(owner_private_key);
        let derived_owner_hash = poseidon::bn254::hash_2([
            derived_owner_public_point.x,
            derived_owner_public_point.y,
        ]);
        assert_eq(derived_owner_hash, old_note.owner, "Owner private key mismatch for old note");
    }

    let old_note_hash = note_hash(old_note);
    let derived_nullifier = poseidon::bn254::hash_3([
        old_note_hash,
        owner_private_key.hi,
        owner_private_key.lo,
    ]);
    assert_eq(derived_nullifier, nullifier, "Nullifier does not match");

    let calculated_merkle_root = compute_merkle_proof(old_note_hash, merkle_index, merkle_path);
    if is_dummy {
        assert_eq(old_note.amount, 0, "Dummy note amount must be zero");
    } else {
        assert(old_note.amount > 0, "Old note amount must be greater than zero");
        assert_eq(calculated_merkle_root, merkle_root, "Merkle root does not match");
    }
}

fn verify_new_note(
    new_note: Note,
    new_note_hash: Field,
    pbm_token_id: u32,
    receiver_public_point: std::embedded_curve_ops::EmbeddedCurvePoint,
    donor_public_point: std::embedded_curve_ops::EmbeddedCurvePoint,
) {
    assert_eq(note_hash(new_note), new_note_hash, "New note hash does not match");

    assert_eq(new_note.pbm_token_id, pbm_token_id, "PBM Token ID does not match for new note");

    let derived_receiver_hash = poseidon::bn254::hash_2([
        receiver_public_point.x,
        receiver_public_point.y,
    ]);
    assert_eq(new_note.owner, derived_receiver_hash, "Receiver public key mismatch for new note");

    let derived_donor_hash = poseidon::bn254::hash_2([
        donor_public_point.x,
        donor_public_point.y,
    ]);
    assert_eq(new_note.donor, derived_donor_hash, "Donor public key mismatch for new note");
}

struct Scalar256bit {
    low: u128,
    high: u128,
}

struct Ciphertext {
    low: Field,
    high: Field,
}

fn encrypt_128bit_with_curve_point(
    secret: u128,
    shared_point: std::embedded_curve_ops::EmbeddedCurvePoint,
    salt: Field,
) -> Field {
    let keystream = poseidon::bn254::hash_2([shared_point.x, salt]);
    let encrypted_secret = (secret as Field) + keystream;
    encrypted_secret
}

fn verify_encryption(
    encryption_randomness: std::embedded_curve_ops::EmbeddedCurveScalar,
    public_point: std::embedded_curve_ops::EmbeddedCurvePoint,
    ephemeral_public_point: std::embedded_curve_ops::EmbeddedCurvePoint,
    shared_secret: Scalar256bit,
    encrypted_key: Ciphertext,
) {
    {
        let derived_ephemeral_point = std::embedded_curve_ops::fixed_base_scalar_mul(encryption_randomness);
        assert_eq(derived_ephemeral_point.x, ephemeral_public_point.x, "Ephemeral public point X mismatch");
        assert_eq(derived_ephemeral_point.y, ephemeral_public_point.y, "Ephemeral public point Y mismatch");
    }

    let shared_point: std::embedded_curve_ops::EmbeddedCurvePoint = std::embedded_curve_ops::multi_scalar_mul([public_point], [encryption_randomness]);

    let derived_encrypted_key_low = encrypt_128bit_with_curve_point(shared_secret.low, shared_point, 1);
    let derived_encrypted_key_high = encrypt_128bit_with_curve_point(shared_secret.high, shared_point, 2);

    assert_eq(derived_encrypted_key_low, encrypted_key.low, "Encrypted key low mismatch");
    assert_eq(derived_encrypted_key_high, encrypted_key.high, "Encrypted key high mismatch");
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

#[test]
fn test_compute_merkle_proof() {
    let leaf = 0x1234;
    
    let node_a = 0x5678;
    let node_c = 0x9abc;
    let node_e = 0xdef0;

    let path = [node_a, node_c, node_e];
    let index = 2; // 010 in binary

    let level_1 = poseidon::bn254::hash_2([leaf, node_a]);
    
    let level_2 = poseidon::bn254::hash_2([node_c, level_1]);
    
    let expected_root = poseidon::bn254::hash_2([level_2, node_e]);

    let calculated_root = compute_merkle_proof(leaf, index, path);
    
    assert(calculated_root == expected_root);
}

#[test]
fn test_merkle_proof_different_index() {
    let leaf = 0x111;
    let sibling = 0x222;
    let path = [sibling, 0x333, 0x444];
    
    let root_0 = compute_merkle_proof(leaf, 0, path);
    
    let root_1 = compute_merkle_proof(leaf, 1, path);
    
    assert(root_0 != root_1);
}

#[test]
fn test_verify_encryption_success() {
    let recipient_priv_key = std::embedded_curve_ops::EmbeddedCurveScalar {
        lo: 0x11111,
        hi: 0x22222,
    };
    let recipient_pub_point = std::embedded_curve_ops::fixed_base_scalar_mul(recipient_priv_key);

    
    let payload = Scalar256bit {
        low: 100,
        high: 200,
    };

    let randomness = std::embedded_curve_ops::EmbeddedCurveScalar {
        lo: 0xabcdef,
        hi: 0x123456,
    };
    
    let ephemeral_pub_point = std::embedded_curve_ops::fixed_base_scalar_mul(randomness);

    let shared_point_sender = std::embedded_curve_ops::multi_scalar_mul([recipient_pub_point], [randomness]);
    
    let k_low = poseidon::bn254::hash_2([shared_point_sender.x, 1]);
    let k_high = poseidon::bn254::hash_2([shared_point_sender.x, 2]);

    let expected_ciphertext = Ciphertext {
        low: (payload.low as Field) + k_low,
        high: (payload.high as Field) + k_high,
    };

    verify_encryption(
        randomness,
        recipient_pub_point,
        ephemeral_pub_point,
        payload,
        expected_ciphertext
    );
}

#[test(should_fail)]
fn test_fail_wrong_randomness() {
    let recipient_priv_key = std::embedded_curve_ops::EmbeddedCurveScalar {
        lo: 0x11111,
        hi: 0x22222,
    };
    let recipient_pub = std::embedded_curve_ops::fixed_base_scalar_mul(recipient_priv_key);
    
    let randomness_a = std::embedded_curve_ops::EmbeddedCurveScalar {
        lo: 111,
        hi: 111,
    };
    let randomness_b = std::embedded_curve_ops::EmbeddedCurveScalar {
        lo: 222,
        hi: 222,
    };

    let ephemeral_real = std::embedded_curve_ops::fixed_base_scalar_mul(randomness_a);

    let payload = Scalar256bit { low: 1, high: 1 };
    let dummy_cipher = Ciphertext { low: 0, high: 0 };

    verify_encryption(
        randomness_b, 
        recipient_pub, 
        ephemeral_real, 
        payload, 
        dummy_cipher
    );
}

fn decrypt(
    encrypted_key: Ciphertext,
    shared_point: std::embedded_curve_ops::EmbeddedCurvePoint,
) -> Scalar256bit {
    let keystream_low = poseidon::bn254::hash_2([shared_point.x, 1]);
    let keystream_high = poseidon::bn254::hash_2([shared_point.x, 2]);

    let decrypted_low = (encrypted_key.low - keystream_low) as u128;
    let decrypted_high = (encrypted_key.high - keystream_high) as u128;

    Scalar256bit {
        low: decrypted_low,
        high: decrypted_high,
    }
}

#[test]
fn test_decrypt() {
    let recipient_priv_key = std::embedded_curve_ops::EmbeddedCurveScalar {
        lo: 0x11111,
        hi: 0x22222,
    };
    let recipient_pub_point = std::embedded_curve_ops::fixed_base_scalar_mul(recipient_priv_key);

    
    let original_payload = Scalar256bit {
        low: 123456789,
        high: 987654321,
    };

    let randomness = std::embedded_curve_ops::EmbeddedCurveScalar {
        lo: 0xabcdef,
        hi: 0x123456,
    };
    
    let ephemeral_pub_point = std::embedded_curve_ops::fixed_base_scalar_mul(randomness);

    let shared_point_sender = std::embedded_curve_ops::multi_scalar_mul([recipient_pub_point], [randomness]);
    
    let ciphertext = Ciphertext {
        low: encrypt_128bit_with_curve_point(original_payload.low, shared_point_sender, 1),
        high: encrypt_128bit_with_curve_point(original_payload.high, shared_point_sender, 2),
    };

    verify_encryption(
        randomness,
        recipient_pub_point,
        ephemeral_pub_point,
        original_payload,
        ciphertext,
    );

    
    let shared_point_recipient = std::embedded_curve_ops::multi_scalar_mul([ephemeral_pub_point], [recipient_priv_key]);

    let decrypted_payload = decrypt(ciphertext, shared_point_recipient);

    assert(decrypted_payload.low == original_payload.low);
    assert(decrypted_payload.high == original_payload.high);
}
