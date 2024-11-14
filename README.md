# TNG

## What is TNG?

TNG (TEE Network Gateway) is a tool for establishing secure communication tunnels, supporting various inbound and outbound traffic methods. It also provides secure session capabilities based on remote attestation (Remote Attestation). By configuring different ingress (Ingress) and egress (Egress) endpoints, users can flexibly control the encryption and decryption of traffic without modifying existing applications.

## Usage

The simplest way to launch a TNG instance is the `launch` subcommand. Here is the usage:

```txt
Usage: tng launch [OPTIONS]

Options:
  -c, --config-file <CONFIG_FILE>
      --config-content <CONFIG_CONTENT>
  -h, --help                             Print help
```

You should provide a JSON config file, or provide configuration content in JSON directly from the command line arguments, which will be used to configure the TNG instance.

Check the [reference document](docs/configuration.md) for the configuration. 

## Build

### Build and run with the docker image

It is recommend to build TNG with docker. Here are the steps.

1. Pull the code

2. Pull the dependencies

```sh
cd tng
git submodule update --init
```

3. Build with docker

```sh
docker build -t tng:latest --target tng-release -f Dockerfile .
```

Now we have got the docker image `tng:latest`.

4. Run tng

```sh
docker run -it --rm --network host tng:latest tng launch --config-content='<your config json string>'
```


### Create a TNG tarball

1. First you should build `tng:latest` docker image with the steps above.

2. Then run the script to package a tarball

```sh
./pack-sdk.sh
```

The tarball will be generated with name `tng-<version>.tar.gz`

3. To install the tarball in a new environment

```sh
tar -xvf tng-*.tar.gz -C /
```

To run the tng binary, you also need to install some dependencies. For ubuntu20.04:

```
apt-get install -y libssl1.1 iptables
```

4. Update iptables

You may need to switch to `iptanles-nft` if you are using a newer kernel on which `iptables-legacy` may not work.

```sh
update-alternatives --set iptables /usr/sbin/iptables-nft
```

5. Run tng

```sh
/opt/tng-0.1.0/bin/tng launch --config-content='<your config json string>'
```


6. To uninstall it, just remove the dir

```sh
rm -rf /opt/tng-*
```

## Example

You can get some examples from the [integration test cases](./tests/).

## Contribution

We welcome community contributions to make TNG a better tool for confidential computing scenarios! If you have any questions or suggestions, feel free to submit an Issue or Pull Request.

## License

Apache-2.0
