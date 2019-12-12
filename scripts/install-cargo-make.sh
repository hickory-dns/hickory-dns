#!/bin/sh

set -e

## This must run after OpenSSL installation
CARGO_MAKE_VER=0.24.1

# if it's already installed, skip
#if cargo make --version ; then exit 0 ; fi

if ver ; then OS="windows" ;
elif [[ "$(uname)" == "Darwin" ]] ; then OS="darwin" ;
elif [[ "$(uname)" == "Linux" ]] ; then OS="linux" ;
else OS=unknown ;
fi

case $OS in
    "windows")
        CARGO_MAKE_URL="https://github.com/sagiegurari/cargo-make/releases/download/${CARGO_MAKE_VER:?}/cargo-make-v${CARGO_MAKE_VER:?}-pc-windows-msvc.zip"

        echo "----> downloading ${CARGO_MAKE_URL}"
        wget -O cargo-make.zip ${CARGO_MAKE_URL:?}
        unzip cargo-make.zip
        
        cp -n cargo-make-v${CARGO_MAKE_VER:?}-pc-windows-msvc/cargo-make ${HOME}/.cargo/bin/cargo-make
    ;;
    "darwin")
        CARGO_MAKE_URL="https://github.com/sagiegurari/cargo-make/releases/download/${CARGO_MAKE_VER:?}/cargo-make-v${CARGO_MAKE_VER:?}-x86_64-apple-darwin.zip"

        echo "----> downloading ${CARGO_MAKE_URL}"
        wget -O cargo-make.zip ${CARGO_MAKE_URL:?}
        unzip cargo-make.zip

        cp -n cargo-make-v${CARGO_MAKE_VER:?}-x86_64-apple-darwin/cargo-make ${HOME}/.cargo/bin/cargo-make
    ;;
    "linux")
        CARGO_MAKE_URL="https://github.com/sagiegurari/cargo-make/releases/download/${CARGO_MAKE_VER:?}/cargo-make-v${CARGO_MAKE_VER:?}-x86_64-unknown-linux-musl.zip"

        echo "----> downloading ${CARGO_MAKE_URL}"
        wget -O cargo-make.zip ${CARGO_MAKE_URL:?}
        unzip cargo-make.zip

        cp -n cargo-make-v${CARGO_MAKE_VER:?}-x86_64-unknown-linux-musl ${HOME}/.cargo/bin/cargo-make
    ;;
    *)
        # TOO BAD, must compile
        echo "----> cargo install cargo-make"
        cargo install -f cargo-make
    ;;
esac

echo "----> testing cargo-make"
cargo make --version