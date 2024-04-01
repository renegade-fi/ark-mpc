### Installation Steps
1. Run `git submodule update --init --recursive` to clone the submodules in this repo.
2. Install `libsodium` & `gmp` via:
```zsh
brew install libsodium gmp boost ntl openssl
yum install libsodium gmp boost ntl openssl
apt-get install libsodium gmp boost ntl openssl
```
based on your local package manager.