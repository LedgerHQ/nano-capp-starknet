Use [ledger_app_builder](https://github.com/LedgerHQ/ledger-app-builder)

```
git clone (https://github.com/LedgerHQ/ledger-app-builder
cd ledger-app-builder
docker build -t ledger-starknet-app-builder:latest .
cd app
git clone https://github.com/yogh333/nano-app-starknet-c
cd ..
docker run --rm -ti -v $(pwd)/app:/app ledger-starknet-app-builder:latest
BOLOS_SDK=$NANOSP_SDK make
```