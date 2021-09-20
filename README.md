AWS KMS CA
----------

**WARNING** this is not something you should use unless you know **exactly** what you are doing, and why.   

Tools for assembling an X.509 certificate and sending it to an AWS KMS asymmetric CMK for signing.

Supported Key Specs
-------------------
 * P256
 * P384


Examples
--------
All examples assume the following prereqs:
 * an AWS KMS CMK created with a supported keyspec, optionally a key alias for the CMK
 * ARN for the CMK/Alias,
 * AWS CLI credentials already provisioned to access the CMK for the `sign` function


**Creating a self-signed root CA**  
create the self-signed CA root certificate, using the CMK for signing.
```
cargo run --example mk_ca_cert -- --days 3650  --region us-east-2 --key_id arn:aws:kms:us-east-2:999999999999:key/00000000-0000-0000-0000-00000000000
```
copy the output into a file, e.g. `ca.pem`, and use OpenSSL to inspect the CA cert contents:
```
openssl x509 -inform PEM -in ca.pem -text -noout
```
Make note of the `X509v3 Authority Key Identifier` value in the `X509v3 extensions` section
```
X509v3 extensions:
    ...
    X509v3 Authority Key Identifier: 
        keyid:C3:99:25:36:9A:E4:0A:E8:8C:F2:31:90:F8:CD:4C:59:7B:6F:04:E4:CF:3E:E9:6D:FA:21:23:00:58:E9:88:C2
```
You will need the authority key identifier for use signing server and client certs.
The above example will be used in subsequent examples as the `--auth-key-id` paramater value:
```
C39925369AE40AE88CF23190F8CD4C597B6F04E4CF3EE96DFA21230058E988C2
```


**Creating a server certificate that is signed by our KMS CA**  
create a server (named _somewhere_)private-key and certificate signed by the CA.  
```
cargo run --example mk_server_cert -- --days 365  --region us-east-2 --key-id arn:aws:kms:us-east-2:999999999999:key/00000000-0000-0000-0000-00000000000 --dns-name "localhost" --ip-addr "127.0.0.1" --ip-addr "0:0:0:0:0:0:0:1"a --common-name 'somewhere' --auth-key-id C39925369AE40AE88CF23190F8CD4C597B6F04E4CF3EE96DFA21230058E988C2 --signing-algorithm ECDSA_SHA_256
```
copy the output into a file, e.g. `server.pem`, and use OpenSSL to inspect the CA cert contents:
```
openssl x509 -inform PEM -in server.pem -text -noout
```
verify the trust chain signature
```
openssl verify -trusted ca.pem server.pem
```


**Creating a client certificate that is signed by our KMS CA**  
create a client (named _someone_) private-key and certificate signed by the CA.  
```
cargo run --example mk_client_cert -- --days 365  --region us-east-2 --key-id arn:aws:kms:us-east-2:999999999999:key/00000000-0000-0000-0000-00000000000 --common-name 'someone' --auth-key-id C39925369AE40AE88CF23190F8CD4C597B6F04E4CF3EE96DFA21230058E988C2 --signing-algorithm ECDSA_SHA_256
```
copy the output into a file, e.g. `client.pem`, and use OpenSSL to inspect the CA cert contents:
```
openssl x509 -inform PEM -in client.pem -text -noout
```
verify the trust chain signature
```
openssl verify -trusted ca.pem client.pem
```


**Getting the CA's public key**  
not normally needed, but can be useful to verify the `Subject Public Key Info` claim in the root CA's cert. 
```
cargo run --example get_cmk_pkey -- --region us-east-2 --key-id arn:aws:kms:us-east-2:999999999999:key/00000000-0000-0000-0000-00000000000
```


Resources
---------
https://tools.ietf.org/html/rfc5280
https://tools.ietf.org/html/rfc5480

https://cipherious.wordpress.com/2013/05/13/constructing-an-x-509-certificate-using-asn-1/
