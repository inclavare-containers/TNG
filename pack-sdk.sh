#!/bin/bash

set -e

trap 'catch' ERR
catch() {
  echo "An error has occurred. Exit now"
}

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
commit_id=$(git rev-parse HEAD)
echo "Packing for tng version: ${version} commit-id: {commit_id}"
echo "$commit_id" > $temp_dir/.commit-id

# Copy files from pre-built docker image
id=$(docker create tng:latest)
mkdir -p $temp_dir/bin/
mkdir -p $temp_dir/lib/
echo "Copying file from container"
docker cp ${id}:/usr/local/bin/tng $temp_dir/bin/
docker cp ${id}:/usr/local/bin/envoy-static $temp_dir/bin/envoy-static.real
docker cp ${id}:/usr/local/lib/rats-rs/librats_rs.so $temp_dir/lib/

echo "Copying glibc stuffs from container"
# Also copy dependencies libraries
dependencies=$(docker run -it --rm tng:latest ldd /usr/local/bin/envoy-static 2>/dev/null)
echo "$dependencies" | while read -r line; do
    # Check if the line not contains '=>'
    if ! echo "$line" | grep -q '=>'; then
        # Extract the path, ensuring it starts with /
        
        if lib_path=$(echo "$line" | awk '{print $1}' | grep '^/' && true); then
            echo "Copy dependency ${lib_path} ..."
            docker cp -L ${id}:$lib_path $temp_dir/lib/
        fi
    else
        if lib_path=$(echo "$line" | awk -F '=>' '{print $2}' | awk '{print $1}' && true); then
            echo "Copy dependency ${lib_path} ..."
            docker cp -L ${id}:$lib_path $temp_dir/lib/
        fi
    fi
done

echo "Fixing rpath and intercepter"
ld=$(basename `patchelf --print-interpreter $temp_dir/bin/envoy-static.real`)
cat <<EOF >$temp_dir/bin/envoy-static
#!/bin/sh
bin_dir=\$(dirname \`realpath \$0\`)
exec \${bin_dir}/../lib/$ld \${bin_dir}/envoy-static.real "\$@"
EOF
chmod +x $temp_dir/bin/envoy-static
# Fix rpath of executable and library
patchelf --set-interpreter /do-not-run-this-exec-directly $temp_dir/bin/envoy-static.real
patchelf --set-rpath '$ORIGIN/../lib/' $temp_dir/bin/envoy-static.real
patchelf --set-rpath '$ORIGIN/../lib/' $temp_dir/lib/librats_rs.so

docker rm ${id}

# Pack all files to a tar.gz
echo "Packing all files to a tar.gz"
tar_file="tng-$version.tar.gz"
(cd "$temp_dir" && tar czf "../$tar_file" --transform "s|^|/opt/tng-$version/|" .)

# Clean up
rm -rf $temp_dir

echo "Tarball created: $tar_file"



