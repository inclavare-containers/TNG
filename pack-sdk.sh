#!/bin/bash

script_dir=$(dirname `realpath "$0"`)

temp_dir="$script_dir/.package"
mkdir -p "$temp_dir"
rm -rf "$temp_dir"/*

cd $script_dir

# Query version of tng
version=$(grep '^version' Cargo.toml | awk -F' = ' '{print $2}' | tr -d '"')
if [ -z "$version" ]; then
    echo "Failed to retrieve version from Cargo.toml"
    exit 1
fi

# Get commit id of tng
echo "$(git rev-parse HEAD)" > $temp_dir/.commit-id

# Copy files from pre-built docker image
id=$(docker create tng:latest)
mkdir -p $temp_dir/bin/
docker cp ${id}:/usr/local/bin/tng $temp_dir/bin/
docker cp ${id}:/usr/local/bin/envoy-static $temp_dir/bin/
mkdir -p $temp_dir/lib/
docker cp ${id}:/usr/local/lib/rats-rs/librats_rs.so $temp_dir/lib/

docker rm ${id}

# Pack all files to a tar.gz
tar_file="tng-$version.tar.gz"
(cd "$temp_dir" && tar czf "../$tar_file" --transform "s|^|/opt/tng-$version/|" .)

# Clean up
rm -rf $temp_dir

echo "Tarball created: $tar_file"



