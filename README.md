# How to Create a Certificate Authority

What is the fundamental problem that a CA is trying solve? In essence it is trying to solve how to allow two or more parties to communicate with each other, trusting that whomever they are communicating with is infact that intended party. Or put another way, how can person A faithfully communicate with person B digitally without being able to physically verify person B's identity.

The answer to this is through a CA (Certificate Authority) essentially a third party that both parties trust. The CA issues and signs digital certificates that can be used to verify an entity. In this case person B may request a certificate to be used by others to verify itself. The idea being that if person A and B both trust the CA and the CA has given person B a certificate that it signed authenticating person B's identity then person A should trust that person B is who they claim to be if theu present the certificate.

## Certificate Request Process
### CSR
