#!/bin/bash

# http2legacy: https://github.com/XTLS/Xray-core/issues/6797
CGO_LDFLAGS="-Wl,-z,max-page-size=16384" gomobile bind -v -androidapi 21 -tags="with_clash,http2legacy" .
