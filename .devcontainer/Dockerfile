FROM rust:1.85-bookworm AS vscode

WORKDIR /workspace

RUN <<EOF
apt-get update
apt-get install -y git vim curl npm
rustup component add rustfmt rust-analyzer rust-docs
npm install -g @google/gemini-cli
EOF
COPY . .
