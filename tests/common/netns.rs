use std::{future::Future, net::Ipv4Addr, os::fd::AsRawFd as _};

use anyhow::{bail, Context, Result};
use futures::TryStreamExt as _;
use rand::{distr::Alphanumeric, Rng as _};
use rtnetlink::{Handle, LinkBridge, LinkUnspec, LinkVeth, RouteMessageBuilder};
use tokio::runtime::Runtime;

#[derive(Debug)]
/// A bridge based network, with a root bridge and an arbitrary number of (network namespace isolated) nodes which can be created dynamically and connected to it.
///
/// Note that due to the route rule, you cannot create two bridge network instances with overlapping subnets simultaneously. Otherwise, you will encounter internet access issues.
pub struct BridgeNetwork {
    handle: Handle,
    bridge: Bridge,
}

#[derive(Debug)]
struct Bridge {
    pub handle: Handle,
    pub bridge_name: String,
    pub bridge_idx: u32,
    pub bridge_addr: Option<Ipv4Addr>,
    pub prefix_len: Option<u8>,
}

impl Bridge {
    async fn query_bridge_idx(handle: &Handle, bridge_name: &str) -> Result<u32> {
        let bridge_idx = handle
            .link()
            .get()
            .match_name(bridge_name.to_owned())
            .execute()
            .try_next()
            .await
            .context("failed to get bridge index")?
            .context("bridge not found")?
            .header
            .index;

        Ok(bridge_idx)
    }

    async fn create_bridge(handle: &Handle, bridge_name: &str) -> Result<Bridge> {
        // Create a bridge
        handle
            .link()
            .add(LinkBridge::new(bridge_name).up().build())
            .execute()
            .await
            .with_context(|| format!("create bridge with name {} failed", bridge_name))?;

        let bridge_idx = Self::query_bridge_idx(handle, bridge_name).await?;

        Ok(Bridge {
            handle: handle.clone(),
            bridge_name: bridge_name.to_owned(),
            bridge_idx,
            bridge_addr: None,
            prefix_len: None,
        })
    }

    async fn init_bridge(&mut self, bridge_ip: &str, prefix_len: u8) -> Result<()> {
        // add ip address to bridge
        let bridge_addr = bridge_ip.parse::<Ipv4Addr>()?;
        self.handle
            .address()
            .add(self.bridge_idx, bridge_addr.into(), prefix_len)
            .execute()
            .await
            .context("add ip address to bridge failed")?;

        self.bridge_addr = Some(bridge_addr);
        self.prefix_len = Some(prefix_len);

        // Enable internet network access.
        let output = tokio::process::Command::new("sh")
            .args(&[
                "-c",
                &format!(
                    "
                set -x ; set -e ;
                exec 2>&1 ;

                echo 1 > /proc/sys/net/ipv4/ip_forward
                iptables -t nat -D POSTROUTING -j TNG_TEST_NETNS_POSTROUTING 2>/dev/null || true
                iptables -t nat -F TNG_TEST_NETNS_POSTROUTING 2>/dev/null || true
                iptables -t nat -X TNG_TEST_NETNS_POSTROUTING 2>/dev/null || true

                iptables -t filter -D FORWARD -j TNG_TEST_NETNS_FORWARD 2>/dev/null || true
                iptables -t filter -F TNG_TEST_NETNS_FORWARD 2>/dev/null || true
                iptables -t filter -X TNG_TEST_NETNS_FORWARD 2>/dev/null || true

                iptables -t nat -N TNG_TEST_NETNS_POSTROUTING
                iptables -t nat -A TNG_TEST_NETNS_POSTROUTING -s {}/{} ! -o {} -j MASQUERADE
                iptables -t nat -A POSTROUTING -j TNG_TEST_NETNS_POSTROUTING

                iptables -t filter -N TNG_TEST_NETNS_FORWARD
                iptables -t filter -A TNG_TEST_NETNS_FORWARD -o {} -j ACCEPT
                iptables -t filter -A TNG_TEST_NETNS_FORWARD -i {} -o {} -j ACCEPT
                iptables -t filter -A TNG_TEST_NETNS_FORWARD -i {} ! -o {} -j ACCEPT
                iptables -t filter -A FORWARD -j TNG_TEST_NETNS_FORWARD
                ",
                    bridge_addr.to_string(),
                    prefix_len,
                    self.bridge_name,
                    self.bridge_name,
                    self.bridge_name,
                    self.bridge_name,
                    self.bridge_name,
                    self.bridge_name
                ),
            ])
            .output()
            .await?;

        if !output.status.success() {
            bail!(
                "exit code: {:?}\nstdout: {}\nstderr: {}",
                output.status.code(),
                &String::from_utf8_lossy(&output.stdout),
                &String::from_utf8_lossy(&output.stderr)
            )
        }

        Ok(())
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let res = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                // Remove iptables rules used for network access.
                match (self.bridge_addr, self.prefix_len) {
                    (Some(_bridge_addr), Some(_prefix_len)) => {// The bridge network has been initialized.
                        let output = tokio::process::Command::new("sh")
                            .args(&[
                                "-c",
                                &format!(
                                    "
                                    set -x ; set -e ;
                                    exec 2>&1 ;
                        
                                    echo 1 > /proc/sys/net/ipv4/ip_forward
                                    iptables -t nat -D POSTROUTING -j TNG_TEST_NETNS_POSTROUTING 2>/dev/null || true
                                    iptables -t nat -F TNG_TEST_NETNS_POSTROUTING 2>/dev/null || true
                                    iptables -t nat -X TNG_TEST_NETNS_POSTROUTING 2>/dev/null || true


                                    iptables -t filter -D FORWARD -j TNG_TEST_NETNS_FORWARD 2>/dev/null || true
                                    iptables -t filter -F TNG_TEST_NETNS_FORWARD 2>/dev/null || true
                                    iptables -t filter -X TNG_TEST_NETNS_FORWARD 2>/dev/null || true
                                    ",
                                ),
                            ])
                            .output()
                            .await?;

                        if !output.status.success() {
                            bail!(
                                "exit code: {:?}\nstdout: {}\nstderr: {}",
                                output.status.code(),
                                &String::from_utf8_lossy(&output.stdout),
                                &String::from_utf8_lossy(&output.stderr)
                            )
                        }
                    }
                    _ => {
                        // Skip
                    }
                }

                self.handle
                    .link()
                    .del(self.bridge_idx)
                    .execute()
                    .await
                    .context("Failed to delete bridge")?;

                Ok::<_, anyhow::Error>(())
            })
        })
        .context("drop bridge network failed");

        if let Err(error) = res {
            tracing::warn!(?error)
        }
    }
}

impl BridgeNetwork {
    pub async fn new(bridge_ip: &str, prefix_len: u8) -> Result<Self> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        // Generate a random bridge name
        let random_part: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(5) // Fixed length characters
            .map(char::from)
            .collect();
        let bridge_name = format!("tngtest-br{}", random_part);

        let mut bridge = Bridge::create_bridge(&handle, &bridge_name).await?;

        bridge.init_bridge(bridge_ip, prefix_len).await?;

        Ok(Self { handle, bridge })
    }

    pub async fn new_node(&self, node_ip: &str) -> Result<Node> {
        let veth_pair = VethPair::create_veth_pair(&self.handle).await?;
        veth_pair
            .add_one_side_to_bridge(self.bridge.bridge_idx)
            .await?;

        let node = Node::create_node(&self.handle, veth_pair).await?;

        node.init_node_network(
            node_ip,
            self.bridge.bridge_addr.context(
                "the bridge addr length is not set, maye be the bridge is not initialized yet",
            )?,
            self.bridge.prefix_len.context(
                "the bridge prefix length is not set, maye be the bridge is not initialized yet",
            )?,
        )
        .await?;
        Ok(node)
    }
}

#[derive(Debug)]
struct VethPair {
    handle: Handle,
    veth_idx: u32,
    veth_2_idx: u32,
}

impl VethPair {
    async fn create_veth_pair(handle: &Handle) -> Result<Self> {
        // Generate a random veth name
        let random_part: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(2) // Fixed length characters
            .map(char::from)
            .collect();
        let veth: String = format!("tngtest-veth{}o", random_part);
        let veth_2: String = format!("tngtest-veth{}i", random_part);

        handle
            .link()
            .add(LinkVeth::new(&veth, &veth_2).up().build())
            .execute()
            .await
            .with_context(|| format!("create veth pair {veth} and {veth_2} failed"))?;

        let veth_idx = handle
            .link()
            .get()
            .match_name(veth.clone())
            .execute()
            .try_next()
            .await
            .context("failed to get veth index")?
            .context("veth not found")?
            .header
            .index;

        let veth_2_idx = handle
            .link()
            .get()
            .match_name(veth_2.clone())
            .execute()
            .try_next()
            .await
            .context("failed to get veth index")?
            .context("veth not found")?
            .header
            .index;

        Ok(Self {
            handle: handle.clone(),
            veth_idx,
            veth_2_idx,
        })
    }

    async fn add_one_side_to_bridge(&self, bridge_idx: u32) -> Result<()> {
        // set first veth to bridge
        self.handle
            .link()
            .set(
                LinkUnspec::new_with_index(self.veth_idx)
                    .controller(bridge_idx)
                    .build(),
            )
            .execute()
            .await
            .with_context(|| {
                format!(
                    "set veth with idx {} to bridge with idx {} failed",
                    self.veth_idx, bridge_idx
                )
            })?;

        Ok(())
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        tokio::task::block_in_place(|| {
            let res = tokio::runtime::Handle::current()
                .block_on(async {
                    // We don't need to delete the second side of the veth pair, because it will be deleted when the first side is deleted.
                    self.handle
                        .link()
                        .del(self.veth_idx)
                        .execute()
                        .await
                        .context("Failed to delete the bridge side of the veth pair")?;

                    Ok::<_, anyhow::Error>(())
                })
                .context("drop veth pair failed");
            if let Err(error) = res {
                tracing::warn!(?error)
            }
        })
    }
}

#[derive(Debug)]
pub struct Node {
    handle: Handle,
    netns: Option<netns_rs::NetNs>,
    veth_pair: VethPair,
    tokio_rt: Option<Runtime>,
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(tokio_rt) = self.tokio_rt.take() {
            tokio_rt.shutdown_background();
        }

        if let Some(netns) = self.netns.take() {
            let res = netns.remove().context("Failed to delete netns");
            if let Err(error) = res {
                tracing::warn!(?error)
            }
        }
    }
}

impl Node {
    async fn create_node(handle: &Handle, veth_pair: VethPair) -> Result<Self> {
        let random_part: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(6) // Fixed length characters
            .map(char::from)
            .collect();
        let netns_name: String = format!("tngtest-ns{}", random_part);
        let netns = netns_rs::NetNs::new(netns_name)?;

        let tokio_rt = Some(
            netns
                .run(|_netns| {
                    // Spawn a new multi thread runtime for executing async tasks in the netns
                    tokio::runtime::Builder::new_multi_thread()
                        .enable_all()
                        .build()
                })
                .map_err(anyhow::Error::from)
                .and_then(|r| r.map_err(anyhow::Error::from))
                .context("Failed to create tokio runtime in netns")?,
        );

        Ok(Self {
            handle: handle.clone(),
            netns: Some(netns),
            veth_pair,
            tokio_rt,
        })
    }

    async fn init_node_network(
        &self,
        node_ip: &str,
        bridge_addr: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<()> {
        let Some(netns) = &self.netns else {
            bail!("the node has been dropped")
        };

        let veth_2_idx = self.veth_pair.veth_2_idx;

        // set veth to the process network namespace
        self.handle
            .link()
            .set(
                LinkUnspec::new_with_index(veth_2_idx)
                    .setns_by_fd(netns.file().as_raw_fd())
                    .build(),
            )
            .execute()
            .await
            .with_context(|| {
                format!(
                    "set veth with idx {veth_2_idx} to netns {:?} failed",
                    netns.file()
                )
            })?;

        let veth_2_addr = std::net::IpAddr::V4(node_ip.parse::<Ipv4Addr>()?);
        self.run(async move {
            // We have to create a new rtnetlink connection here, because we are in a different netns
            let (connection, handle_in_newns, _) = rtnetlink::new_connection()?;
            tokio::spawn(connection);

            // set ip address to veth
            handle_in_newns
                .address()
                .add(veth_2_idx, veth_2_addr, prefix_len)
                .execute()
                .await
                .with_context(|| format!("add ip address to veth with idx {veth_2_idx} failed"))?;

            // set veth to up
            handle_in_newns
                .link()
                .set(LinkUnspec::new_with_index(veth_2_idx).up().build())
                .execute()
                .await
                .with_context(|| format!("set veth with idx {veth_2_idx} to up failed"))?;

            // set lo to up
            handle_in_newns
                .link()
                .set(LinkUnspec::new_with_name("lo").up().build())
                .execute()
                .await
                .context("set lo interface to up failed")?;

            // set default route to the bridge, so that we can reach the internet network
            handle_in_newns
                .route()
                .add(
                    RouteMessageBuilder::<Ipv4Addr>::new()
                        .gateway(bridge_addr)
                        .build(),
                )
                .execute()
                .await
                .with_context(|| format!("add default route in new netns failed"))?;

            Ok::<_, anyhow::Error>(())
        })
        .await??;

        Ok(())
    }

    /// Create a multi thread runtime to run the future in the network namespace. This function will
    /// wait for the future to complete and return the output of the future. If the future spawns
    /// other tasks, they will be spawned in the same network namespace, and will continue to run in
    /// background, until the Node is dropped.
    pub async fn run<F>(&self, future: F) -> Result<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let Some(netns) = &self.netns else {
            bail!("the node has been dropped")
        };

        let join_handle = netns
            .run(|_netns| {
                let join_handle = self
                    .tokio_rt
                    .as_ref()
                    .context(
                        "Failed to get tokio runtime instance, maybe forget to init the Node?",
                    )?
                    .spawn(future);

                Ok::<_, anyhow::Error>(join_handle)
            })
            .context("Failed to swith network namespace")??;

        join_handle.await.with_context(|| {
            format!(
                "Failed to run the future in network namespace {:?}",
                netns.path()
            )
        })
    }
}

#[cfg(test)]
mod tests {

    use anyhow::Ok;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_single_bridge_network() -> Result<()> {
        let network1 = BridgeNetwork::new("192.168.1.254", 24).await?;
        let network1_node1 = network1.new_node("192.168.1.1").await?;
        let network1_node2 = network1.new_node("192.168.1.2").await?;

        for node in [&network1_node1, &network1_node2] {
            node.run(async move {
                let output = tokio::process::Command::new("sh")
                    .args(&[
                        "-c",
                        "
                        set -x ; set -e ;
                        exec 2>&1 ;
                        
                        ip -4 a | grep 192.168.1. ;
                        ip route show | grep default ;
                        ping 192.168.1.1 -c 1 -W 5 ;
                        ping 192.168.1.2 -c 1 -W 5 ;
                        ping 192.168.1.254 -c 1 -W 5 ;
                        cat /etc/resolv.conf
                        dig @8.8.8.8 connectivitycheck.gstatic.com
                        dig connectivitycheck.gstatic.com
                        curl http://connectivitycheck.gstatic.com/generate_204 --connect-timeout 5;
                        ",
                    ])
                    .output()
                    .await?;

                if !output.status.success() {
                    bail!(
                        "exit code: {:?}\nstdout: {}\nstderr: {}",
                        output.status.code(),
                        &String::from_utf8_lossy(&output.stdout),
                        &String::from_utf8_lossy(&output.stderr)
                    )
                }
                Ok(())
            })
            .await??;
        }

        Ok(())
    }
}
