# Attester

A minimalistic tool that does those things:
 - Obtains an SGX DCAP quote (a.k.a. remote attestation), with the specified challenge embedded as report data
 - Verifies an arbitrary quote, prints quote measurements, and fetches the unique platform identifier

# How to use
```
docker run \
    --device /dev/sgx_enclave \
    --device /dev/sgx_provision \
    -v /etc/sgx_default_qcnl.conf:/etc/sgx_default_qcnl.conf:ro \
    --rm \
    ghcr.io/proofofcloud/attester@sha256:c723f206e1cd16cf6ec4dd04f37249f378edcf9cce7955ba826402b6812b9989 get beefdeed

(replace _beefdeed_ with your challenge)
```

# Output
The output of the get command contains the following: 
 - Raw quote
 - Quote verification report
 - PPID of the machine
