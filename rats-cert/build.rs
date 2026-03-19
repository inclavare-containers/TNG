#[cfg(feature = "attester-coco")]
use ttrpc_codegen::{Codegen, Customize, ProtobufCustomize};

fn main() {
    #[cfg(feature = "attester-coco")]
    {
        // Build for connecting AA with ttrpc
        let protos = vec!["src/tee/coco/protos/attestation-agent.proto"];
        let protobuf_customized = ProtobufCustomize::default().gen_mod_rs(false);

        let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let aa_dir = out_dir.join("attestation-agent").join("ttrpc_protocol");
        let _ = std::fs::create_dir_all(&aa_dir); // This will panic below if the directory failed to create

        Codegen::new()
            .out_dir(&aa_dir)
            .inputs(&protos)
            .include("src/tee/coco/protos")
            .rust_protobuf()
            .customize(Customize {
                async_all: false, // TODO: enable async when async feature of rats-rs is ready
                ..Default::default()
            })
            .rust_protobuf_customize(protobuf_customized)
            .run()
            .expect("Generate ttrpc protocol code failed.");

        fn strip_inner_attribute(path: &std::path::Path) {
            let code = std::fs::read_to_string(path).expect("Failed to read generated file");
            let mut writer = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
            for line in code.lines() {
                if !line.starts_with("//!") && !line.starts_with("#!") {
                    std::io::Write::write_all(&mut writer, line.as_bytes()).unwrap();
                    std::io::Write::write_all(&mut writer, b"\n").unwrap();
                }
            }
        }

        strip_inner_attribute(&aa_dir.join("attestation_agent.rs"));
        strip_inner_attribute(&aa_dir.join("attestation_agent_ttrpc.rs"));
    }

    #[cfg(feature = "verifier-coco")]
    {
        // Build for connecting AS with Grpc
        let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());

        let v1_5_2 = out_dir.join("attestation-service").join("v1_5_2");
        let _ = std::fs::create_dir_all(&v1_5_2); // This will panic below if the directory failed to create
        tonic_build::configure()
            .out_dir(v1_5_2)
            .build_server(false)
            .build_client(true)
            .compile_protos(
                &["src/tee/coco/protos/attestation-service/v1_5_2.proto"],
                &[] as &[&str],
            )
            .expect("Generate grpc protocol code failed.");

        let v1_6_0 = out_dir.join("attestation-service").join("v1_6_0");
        let _ = std::fs::create_dir_all(&v1_6_0); // This will panic below if the directory failed to create
        tonic_build::configure()
            .out_dir(v1_6_0)
            .build_server(false)
            .build_client(true)
            .compile_protos(
                &["src/tee/coco/protos/attestation-service/v1_6_0.proto"],
                &[] as &[&str],
            )
            .expect("Generate grpc protocol code failed.");
    }
}
