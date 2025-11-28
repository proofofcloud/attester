# Attester

A minimalistic tool that does those things:
 - Obtains an SGX DCAP quote (a.k.a. remote attestation), with the specified challenge embedded as report data
 - Verifies an arbitrary quote, prints quote measurements, and fetches the unique platform identifier

# How to use
```
sudo docker run \
    --device /dev/sgx_enclave \
    --device /dev/sgx_provision \
    --rm \
    ghcr.io/proofofcloud/attester@sha256:856659bea241a70de6fc1e7524b84c74d58e2b04a8bf815c87055026ccbf4254 \
    get beefdeed

(replace _beefdeed_ with your challenge)
```

# Output
The output of the get command contains the following: 
 - Raw quote
 - Quote verification report
 - PPID of the machine
