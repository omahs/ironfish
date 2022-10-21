# Running Tests
1. Download [cargo-flamegraph](https://github.com/flamegraph-rs/flamegraph). 
```bash
cargo install flamegraph
```

2. Run the flamegraph in this folder. You will need to run with root permissions and enter password
```bash
cargo build
cargo run flamegraph --root
```

3. SVG image is outputted in the same folder, open with Chrome

