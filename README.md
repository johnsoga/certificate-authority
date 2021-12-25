# How to Create a Certificate Authority

What is the fundamental problem that a CA is trying solve? In essence it is trying to solve how to allow two or more parties to communicate with each other, trusting that whomever they are communicating with is in-fact that intended party. Or put another way, how can Alice faithfully communicate with Bob digitally without being able to physically verify Bob's identity.

The answer to this is through a [CA](https://en.wikipedia.org/wiki/Certificate_authority) ([Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority)) essentially a third party that both parties trust. The CA issues and signs digital certificates that can be used to verify an entity. In this case person B may request a certificate to be used by others to verify itself. In theory, if Alice and Bob both trust the CA, and the CA has given Bob a certificate. A certificate that the CA has signed authenticating its origin. Then, when Alice is presented the Bob's by Bob Alice should trust that she is in fact communicating with Bob

## Certificate Request Process
### CSR
A CSR (Certificate Signing Request) is a request sent to an RA (Registration Authority) for a certificate to be issued.

>*Generally speaking, the CA and RA will both be within the same organization so the term CA will be used here instead as a generic term.*

[CSR's](https://en.wikipedia.org/wiki/Certificate_signing_request) are [PKCS#10](https://tools.ietf.org/html/rfc2986) formatted documents defined using the [ASN.1](https://en.wikipedia.org/wiki/ASN.1) structure as outlined in specification [RFC 2986](https://tools.ietf.org/html/rfc2986). PKCS#10 is a binary format and as such is often instead encoded further via the BASE64 [PEM](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail) format as defined in [RFC 7468](https://tools.ietf.org/html/rfc7468) for general ease of use.

Let's take a look at the `example.com.csr.pem` CSR in `examples/example1/csr`, run `openssl asn1parse -i -inform PEM -dump -in example.com.csr.pem`:

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
  0000 - 00 30 82 01 0a 02 82 01-01 00 d8 56 7c 39 c5 2a   .0.........V|9.*
  0010 - 08 9a 46 4b 65 0e 51 a3-7a 7a da 5d 9c 08 96 d4   ..FKe.Q.zz.]....
  0020 - c5 ce bb 8b 28 05 87 0d-5d 28 0e 29 24 8a 50 5a   ....(...](.)$.PZ
  0030 - c8 98 55 e6 97 e2 73 7e-46 f5 d5 90 6a 76 85 99   ..U...s~F...jv..
  0040 - 97 22 a3 92 44 75 fd c7-85 14 6f c8 d1 9d 26 42   ."..Du....o...&B
  0050 - b3 eb 56 58 50 84 53 fb-c4 4b bc 41 45 9f b5 b7   ..VXP.S..K.AE...
  0060 - f6 7b ce 7f 1a 0a 39 58-8d f2 cc b8 bc 67 e3 29   .{....9X.....g.)
  0070 - 19 69 38 a3 43 07 63 d6-0d d1 07 53 7a bc c4 01   .i8.C.c....Sz...
  0080 - 00 0c ca 7c 37 ed a0 13-83 fd e0 cf 1a e2 3e 91   ...|7.........>.
  0090 - fb 8d 21 b8 c7 97 92 c2-c5 65 66 a7 6d 39 5f 85   ..!......ef.m9_.
  00a0 - 8b a0 d4 22 36 8f 72 5e-53 db 4a ff 16 ff 7a 00   ..."6.r^S.J...z.
  00b0 - ed 2d 04 6b d7 a9 97 45-b1 da 59 a2 b3 ad c8 d8   .-.k...E..Y.....
  00c0 - 4e 30 d7 c8 4a b9 ce 11-db 8e b8 92 29 4e c0 0b   N0..J.......)N..
  00d0 - d8 7a f1 69 e1 36 a6 3d-19 6c 37 73 c4 e1 c9 6f   .z.i.6.=.l7s...o
  00e0 - 6e 73 9d 64 99 76 b4 33-8d f9 29 70 22 b7 24 2c   ns.d.v.3..)p".$,
  00f0 - d6 d8 ed f4 bd e7 c9 47-85 13 b8 ee d8 2d bb b3   .......G.....-..
  0100 - 35 7a f0 34 09 14 d1 08-d8 a5 02 03 01 00 01      5z.4...........
369:d=2  hl=2 l=   0 cons:   cont [ 0 ]
371:d=1  hl=2 l=  13 cons:  SEQUENCE
373:d=2  hl=2 l=   9 prim:   OBJECT            :sha256WithRSAEncryption
384:d=2  hl=2 l=   0 prim:   NULL
386:d=1  hl=4 l= 257 prim:  BIT STRING
  0000 - 00 5c 55 e5 ed 63 02 f0-71 fe 07 17 d6 39 5b 48   .\U..c..q....9[H
  0010 - f2 b4 83 b8 38 19 15 c0-68 39 d9 89 08 8c bc e1   ....8...h9......
  0020 - 4a 3e 56 0c a9 f5 38 cb-a3 26 67 ac ae 8e 40 6d   J>V...8..&g...@m
  0030 - e2 17 28 f4 83 1d c4 fe-ff 13 a9 b8 f8 44 5d 5b   ..(..........D][
  0040 - 03 99 2e 07 42 31 03 c9-59 78 b9 cf 95 e9 29 45   ....B1..Yx....)E
  0050 - 71 5c 75 de 38 3d 0e 39-a3 27 cb d5 98 72 e9 6e   q\u.8=.9.'...r.n
  0060 - 27 81 17 0c cb 14 0a 90-34 55 b9 56 38 5c d7 94   '.......4U.V8\..
  0070 - 1e d5 44 62 3c bd 72 26-2d 33 ba a6 72 9e f3 79   ..Db<.r&-3..r..y
  0080 - 3f 07 76 71 d9 31 01 c0-01 a1 55 53 c5 4d 26 6a   ?.vq.1....US.M&j
  0090 - d5 ee db c6 82 98 58 ce-e4 d0 49 8b 41 5a 46 0d   ......X...I.AZF.
  00a0 - 15 74 5b 5e 09 83 37 ac-3c 11 3a 46 fe f4 0f 9b   .t[^..7.<.:F....
  00b0 - 17 98 b2 f8 e1 d7 fe 9d-98 cf 90 ab 33 fe e4 8d   ............3...
  00c0 - eb 6b fa 11 0f 6d 0e 08-1e e7 19 3b aa 77 61 03   .k...m.....;.wa.
  00d0 - 55 2d 2e d7 f8 59 8d ec-9f e1 a1 96 0c 34 23 f9   U-...Y.......4#.
  00e0 - 33 65 33 30 b9 49 83 66-4f d2 d7 5b 71 b4 9c ec   3e30.I.fO..[q...
  00f0 - 5f 8c f8 3e 40 4c 46 77-72 80 e8 7c b7 82 3d 0d   _..>@LFwr..|..=.
  0100 - 0c                                                .
```

Here we can see some important information about the certificate that is being requested to be created. We can see the [DN](https://en.wikipedia.org/wiki/X.509) ([Distinguished Name](https://en.wikipedia.org/wiki/X.509)) which is essentially just information about the entity requesting the certificate this also further elaborated in [RFC 5280](https://tools.ietf.org/html/rfc5280). In this case we can the country `countryName` of the company, name of the company `organizationName`, and the specific domain/entity `commonName` the certificate is being requested for. In case it is not clear this CSR would be for a certificate to be used on a website with the domain `example.com`. There are two more important pieces of information shown as well. The encryption algorithm of the public key to be used in the certificate `rsaEncryption` and the signature algorithm of the CSR `sha256WithRSAEncryption`. This information will be put into the certificate issued by the CA.

## Certificate Chain of Trust
As mentioned earlier a certificate is signed by the CA and created from a CSR. What happens behind the scenes here is that another certificate is actually used to sign the certificate to be created from the CSR by the CA. Let's take a look at how this works.

```
$ openssl x509 -noout -text -in certs/root.cert.pem
        Issuer: C=US, O=Test Company LLC, CN=Test Company Root CA
        Subject: C=US, O=Test Company LLC, CN=Test Company Root CA
        X509v3 Subject Key Identifier:
            09:9A:5F:43:25:6F:47:48:08:32:C5:4E:76:EA:35:03:0C:69:31:92

$ openssl x509 -noout -text -in certs/sub.cert.pem
        Issuer: C=US, O=Test Company LLC, CN=Test Company Root CA
        Subject: C=US, O=Test Company LLC, CN=Test Company Sub CA
        X509v3 Subject Key Identifier:
            50:1F:B1:61:61:55:14:71:AA:6D:2B:78:A6:B8:B6:34:21:52:80:A7
        X509v3 Authority Key Identifier:
            keyid:09:9A:5F:43:25:6F:47:48:08:32:C5:4E:76:EA:35:03:0C:69:31:92

$ openssl x509 -noout -text -in certs/example.com.cert.pem
        Issuer: C=US, O=Test Company LLC, CN=Test Company Sub CA
        Subject: C=US, O=Test Company LLC, CN=example.com
        X509v3 Subject Key Identifier:
            03:87:6C:4B:F3:FC:82:0B:67:49:A9:F4:A8:74:62:4A:60:BB:AC:A7
        X509v3 Authority Key Identifier:
            keyid:50:1F:B1:61:61:55:14:71:AA:6D:2B:78:A6:B8:B6:34:21:52:80:A7
```
Notice at the bottom we have the cert that would eventually be made from the CSR that we looked at earlier. Notice for all 3 certificates there is an `Issuer:` and `Subject:`. You'll notice the information listed on those lines is the DN information that came from a CSR. This information allows us to quickly see who signed and created the certificate the `Issuer:` and the for what entity/domain the certificate was created for the `Subject:` But that information alone would not be sufficiently secure. As just text added to a cert that information could be forged or manipulated.

ASN1 CERT
bash-3.2$ /usr/local/opt/openssl@1.1/bin/openssl asn1parse -i -inform PEM -dump -in certs/example.com.cert.pem

Get Binary format
openssl x509 -in certs/example.com.cert.pem -outform DER
