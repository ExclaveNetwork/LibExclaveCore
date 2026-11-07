#!/bin/bash

FLAVOR="${1}"

case FLAVOR in
  ossRelease)
    CGO_LDFLAGS=-Wl,-z,max-page-size=16384,--pack-dyn-relocs=android
    ANDROID_API=24
    LDFLAGS="-s -buildid="
    ;;
  legacyRelease)
    CGO_LDFLAGS=-Wl,-z,max-page-size=16384
    ANDROID_API=21
    LDFLAGS="-s -buildid="
    ;;
  ossDebug)
    CGO_LDFLAGS=-Wl,-z,max-page-size=16384,--pack-dyn-relocs=android
    ANDROID_API=24
    LDFLAGS=""
    ;;
  legacyDebug)
    CGO_LDFLAGS=-Wl,-z,max-page-size=16384
    ANDROID_API=21
    LDFLAGS=""
    ;;
  *)
    CGO_LDFLAGS=-Wl,-z,max-page-size=16384,--pack-dyn-relocs=android
    ANDROID_API=24
    LDFLAGS="-s -buildid="
    FLAVOR="ossRelease"
    ;;
esac

pushd "$(dirname "$0")"

CGO_LDFLAGS="${CGO_LDFLAGS}" gomobile bind -v -androidapi ${ANDROID_API} -trimpath -ldflags="${LDFLAGS}" -tags="with_clash" -o "./libexclavecore-${FLAVOR}.aar" "github.com/exclavenetwork/libexclavecore" || exit 1

proj=../../app/libs
if [ -d "$proj" ]; then
  cp -vf "./libexclavecore-${FLAVOR}.aar" "$proj"
fi

popd
