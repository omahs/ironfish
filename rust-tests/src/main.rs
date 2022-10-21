extern crate rand;
extern crate hex;

use hex::decode;

use ironfish_rust::MerkleNoteHash;

fn main() {
    let left = decode("a2801e0582bef67bfb1250556a5f163e50d853178e23874457b79b356fc6265f").unwrap();
    let right = decode("81d4d87dd0cbab8ba8371c80b5cc1a4b03f9f7609fe9f038d534d0fc996c5068").unwrap();

    for _ in 1..1000000 {
        let depth = 10;

        let left_hash = MerkleNoteHash::read((&left[..]).as_ref()).unwrap();
        let right_hash = MerkleNoteHash::read((&right[..]).as_ref()).unwrap();

        let converted_depth: usize = depth
            .try_into()
            .unwrap();

        let mut vec = Vec::with_capacity(32);

        MerkleNoteHash::new(MerkleNoteHash::combine_hash(
            converted_depth,
            &left_hash.0,
            &right_hash.0,
        ))
        .write(&mut vec)
        .unwrap();
    }

    println!("Finished");
}
