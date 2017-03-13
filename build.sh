#!/bin/bash
pushd server
CGO_ENABLED=0 go build -v -i -ldflags '-s -w' -o ../bin/sskcp_server
CGO_ENABLED=0 GOOS=darwin go build -v -i -ldflags '-s -w' -o ../bin/sskcp_server_darwin
popd

pushd client
CGO_ENABLED=0 go build -v -i -ldflags '-s -w' -o ../bin/sskcp_client
CGO_ENABLED=0 GOOS=darwin go build -v -i -ldflags '-s -w' -o ../bin/sskcp_client_darwin
popd
