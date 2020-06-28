fn main() {
    prost_build::compile_protos(&["src/dht_pb.proto"], &["src"]).unwrap();
}
