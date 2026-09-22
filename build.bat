@echo off

set CGO_LDFLAGS=-Wl,-z,max-page-size=16384

:: http2legacy: https://github.com/XTLS/Xray-core/issues/6797
gomobile bind -v -androidapi 21 -trimpath -ldflags="-s -buildid=" -tags="with_clash,http2legacy" .
