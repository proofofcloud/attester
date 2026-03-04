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
    ghcr.io/proofofcloud/attester@sha256:2ae052dd244ab12880bf7a77b6580a289761d10bb19764310e4c44bbd8c5f14c \
    get beefdeed

(replace _beefdeed_ with your challenge)
```

# Output
The output of the get command contains the following: 
 - Raw quote
 - Quote verification report
 - PPID of the machine
