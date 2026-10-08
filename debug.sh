#!/bin/bash

CGO_LDFLAGS="-Wl,-z,max-page-size=16384" gomobile bind -v -androidapi 21 -tags="with_clash" .
