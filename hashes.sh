#! /bin/sh

echo "Generating SHA256 Binary Hashes for Release"

echo "SHA256 bin/botb-linux-amd64"
cat bin/botb-linux-amd64 | shasum -a 256
echo "SHA256 bin/botb-darwin-amd64"
cat bin/botb-darwin-amd64 | shasum -a 256
echo "SHA256 bin/botb-linux-386"
cat bin/botb-linux-386 | shasum -a 256
echo "SHA256 bin/botb-darwin-386"
cat bin/botb-darwin-386 | shasum -a 256