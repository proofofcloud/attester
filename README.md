# Attester

A minimalistic tool that does those things:
 - Obtains an SGX DCAP quote (a.k.a. remote attestation), with the specified challenge embedded as report data
 - Verifies an arbitrary quote, prints quote measurements, and fetches the unique platform identifier

# How to use
```
git clone https://github.com/proofofcloud/attester

cd attester

docker build -t attester .

docker run \
   --device /dev/sgx_enclave \
   --device /dev/sgx_provision \
   -v /etc/sgx_default_qcnl.conf:/etc/sgx_default_qcnl.conf:ro \
   --rm attester get beefdeed

(replace _beefdeed_ with your challenge)
```

# Output
The output of the get command contains the following: 
 - Raw quote
 - Quote verification report
 - PPID of the machine
