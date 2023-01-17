use std::{env, time::Instant};

use ironfish_rust::SaplingKey;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};

// Run with:
// cargo run --bin vanity --release f000

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Must provide an address prefix");
        return;
    }

    let str_to_match = &args[1];

    // Uncomment this to set a thread-count
    // let num_threads = 3;
    // rayon::ThreadPoolBuilder::new()
    //     .num_threads(num_threads)
    //     .build_global()
    //     .unwrap();

    println!("Starting...");
    let t = Instant::now();
    loop {
        let x = (0..250_000).into_par_iter().filter_map(|_| {
            let key = SaplingKey::generate_key();
            let pa = key.public_address().hex_public_address();

            match &pa[0..str_to_match.len()] == str_to_match {
                true => {
                    println!(
                        "KEY FOUND: \nsecret: {}\npublic: {}",
                        key.hex_spending_key(),
                        key.public_address().hex_public_address(),
                    );

                    Some(key)
                }
                _ => None,
            }
        });

        let c = &x.count();

        if c >= &1 {
            break;
        }
        let d = t.elapsed();
        println!("Elapsed: {} seconds", d.as_secs());
    }
}
