# How to Create a Certificate Authority

What is the fundamental problem that a CA is trying solve? In essence it is trying to solve how to allow two or more parties to communicate with each other, trusting that whomever they are communicating with is in-fact that intended party. Or put another way, how can Alice faithfully communicate with Bob digitally without being able to physically verify Bob's identity.

The answer to this is through a CA (Certificate Authority) essentially a third party that both parties trust. The CA issues and signs digital certificates that can be used to verify an entity. In this case person B may request a certificate to be used by others to verify itself. In theory, if Alice and Bob both trust the CA, and the CA has given Bob a certificate. A certificate that the CA has signed authenticating its origin. Then, when Alice is presented the Bob's by Bob Alice should trust that she is in fact communicating with Bob

## Certificate Request Process
### CSR
A CSR (Certificate Signing Request) is a request sent to an RA (Registration Authority) for a certificate to be issued.

>*Generally speaking, the CA and RA will both be within the same organization so the term CA will be used here instead as a generic term.*

[CSR's](https://en.wikipedia.org/wiki/Certificate_signing_request) are [PKCS#10](https://tools.ietf.org/html/rfc2986) formatted documents defined using the [ASN.1](https://en.wikipedia.org/wiki/ASN.1) structure as outlined in specification [RFC2986](https://tools.ietf.org/html/rfc2986). PKCS#10 is a binary format and as such is often instead encoded further via the BASE64 [PEM](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail) format as defined in [RFC7468](https://tools.ietf.org/html/rfc7468) for general ease of use.

Let's take a look at the `example.com.csr.pem` CSR in `examples/`:

```
    0:d=0  hl=4 l= 643 cons: SEQUENCE
    4:d=1  hl=4 l= 363 cons:  SEQUENCE
    8:d=2  hl=2 l=   1 prim:   INTEGER           :00
   11:d=2  hl=2 l=  62 cons:   SEQUENCE
   13:d=3  hl=2 l=  11 cons:    SET
   15:d=4  hl=2 l=   9 cons:     SEQUENCE
   17:d=5  hl=2 l=   3 prim:      OBJECT            :countryName
   22:d=5  hl=2 l=   2 prim:      PRINTABLESTRING   :US
   26:d=3  hl=2 l=  25 cons:    SET
   28:d=4  hl=2 l=  23 cons:     SEQUENCE
   30:d=5  hl=2 l=   3 prim:      OBJECT            :organizationName
   35:d=5  hl=2 l=  16 prim:      UTF8STRING        :Test Company LLC
   53:d=3  hl=2 l=  20 cons:    SET
   55:d=4  hl=2 l=  18 cons:     SEQUENCE
   57:d=5  hl=2 l=   3 prim:      OBJECT            :commonName
   62:d=5  hl=2 l=  11 prim:      UTF8STRING        :example.com
   75:d=2  hl=4 l= 290 cons:   SEQUENCE
   79:d=3  hl=2 l=  13 cons:    SEQUENCE
   81:d=4  hl=2 l=   9 prim:     OBJECT            :rsaEncryption
   92:d=4  hl=2 l=   0 prim:     NULL
   94:d=3  hl=4 l= 271 prim:    BIT STRING
  369:d=2  hl=2 l=   0 cons:   cont [ 0 ]
  371:d=1  hl=2 l=  13 cons:  SEQUENCE
  373:d=2  hl=2 l=   9 prim:   OBJECT            :sha256WithRSAEncryption
  384:d=2  hl=2 l=   0 prim:   NULL
  386:d=1  hl=4 l= 257 prim:  BIT STRING
```
