mod common;

use anyhow::Result;
use common::{
    run_test,
    task::{shell::ShellTask, tng::TngInstance, NodeType, Task as _},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    run_test(vec![
        TngInstance::TngClient(
            r#"
                {
                    "add_ingress": [
                        {
                            "http_proxy": {
                                "proxy_listen": {
                                    "host": "0.0.0.0",
                                    "port": 41000
                                },
                                "dst_filter": {
                                    "domain": "*",
                                    "port": 7711
                                }
                            },
                            "verify": {
                                "as_addr": "http://192.168.1.254:8080/",
                                "policy_ids": [
                                    "default"
                                ]
                            }
                        }
                    ]
                }
                "#,
        )
        .boxed(),
        ShellTask {
            name: "bad_client".to_owned(),
            node_type: NodeType::Client,
            script: r#"
                ret=0
                curl 127.0.0.1:41000 --max-time 1 || ret=$?
                if [[ $ret -eq 28 ]] ; then # 28 is timeout
                    echo 'bug detected'
                    exit 1
                fi
            "#
            .to_owned(),
            stop_test_on_finish: true,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}
