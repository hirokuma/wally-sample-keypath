# key path

## NOTICE

This application is intended for Regtest use only.  
No security measures have been implemented.

## prepare

```bash
sudo apt install build-essential pkg-config libtool
```

### libsecp256k1

```bash
git clone https://github.com/bitcoin-core/secp256k1.git
cd secp256k1
git checkout -b v0.7.0 refs/tags/v0.7.0
./autogen.sh
./configure --enable-module-recovery
make
sudo make install
```

### libwally-core

```bash
git clone https://github.com/ElementsProject/libwally-core.git
cd libwally-core
git checkout -b v1.5.1 release_1.5.1
./tools/autogen.sh
./configure --disable-elements --enable-standard-secp --with-system-secp256k1
make
sudo make install
```

## build

```bash
git clone https://github.com/hirokuma/wally-sample-keypath.git
cd wally-sample-keypath
make
```

## Run

### conf

`settings.conf`

```file
network=regtest
```

### Get new address

```bash
./tst newaddr
```

### Get addresses created by this wallet

```bash
./tst addr
```

### Decode raw transaction

```bash
./tst <raw transaction>
```

## Test

Install gcovr

* [Installation — gcovr 8.3 documentation](https://gcovr.com/en/8.3/installation.html)

```shell
$ cd tests
$ make
$ make tests
$ make cov
```

After successful, you can browse `tests/_build/coverage/index.html`.

### Wally API usage test

```shell
$ cd tests
$ make -f Makefile_wally.mk
```
