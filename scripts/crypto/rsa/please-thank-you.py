# utctf-2021 - please and thank you
# https://pottm.com/u/Mnsx9thwSS6qNrG.txt
#
# grab all certs from https://crt.sh, do GCD to break public key, generate private key for CA, sign your own client certificate and authenticate

from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse, getPrime, GCD, isPrime
from Crypto.PublicKey import RSA

# exported from firefox certificate viewer
cert_chain_1 = """
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAwWhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cPR5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdxsxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8ZutmNHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxgZ3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaAFHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6WPTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wlikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQzCkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BImlJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1OyK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90IdshCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6ZvMldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqXnLRbwHOoq7hHwg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygch77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6UA5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sWT8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyHB5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UCB5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUvKBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWnOlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTnjh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbwqHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CIrU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkqhkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZLubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KKNFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7UrTkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdCjNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVcoyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPAmRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57demyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
"""

# certificate log at https://crt.sh/?q=psandqs.dangerous-testing.utctf.live

# https://crt.sh/?id=4202972763
cert_leaf_1 = """
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----

"""

# https://crt.sh/?id=4202980844
cert_leaf_2 = """
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----

"""


with open("cert-leaf-1.pem", "w") as f:
    f.write(cert_leaf_1)
    
with open("cert-leaf-2.pem", "w") as f:
    f.write(cert_leaf_2)
    
with open("cert-chain-1.pem", "w") as f:
    f.write(cert_chain_1)
    
    
# openssl x509 -in cert-leaf-1.pem -text -noout
# openssl x509 -in cert-leaf-2.pem -text -noout
e = 0x10001
n1 = 0xc525905a0ed71274317d4beeca10254c99f9b8406de24835b49b3ac87702794abb382b96651b51c635d717a8f1c11da390f640b8d526ed82906f89bf7befd091f046ca2d9afc0f9b979cf2f37f3291cd123f26ea3c1749c28754407dea91de11e98cfdb0e3d75412bec5b3f06812d4ce3026e3fe904e945c23931faeda3b12d6fce6eb15aa125239778cf6287e4382d8b8a316b7c0ca02988bf06a1c20e7715f9b354c8ca9440e4a4b10255c0d45c66f31b39956d01793546383d6a65a1f668ac9484c4d54d72ebc0586d7a74440db409d4c18df36aa2e111475613aba2f69d08ce1a88fbe4286de8b5d4cfac13a6878a18d6035c72912cf652bf2e46a5a92378a3263656189f9094f047573943d7b73417890644e5c10b8afb6342415e35eb0bf6d3e0fbb99fbdf3108f3f7b34300a1dc30c1c1319f5e6521facf1d2c70ab35c9b012a619de17d7bf715cd22e5bfa28913b648aa6463cd5e14fcb0a9feea650f7de4992b781ae3285851f328746d0cdc434be07e29a157ae769b8794f161ac2b6b986fe3564a823023b4e25c546e7c8cff2560a6b6143cc1426b2d88ae1941a30a830267625f531a6a9335dcf5a178e032a410e5461dae0390482f6d3f58588be961d63c576c9538a6f5ec4a08762d4f1f395a875b7fbb97022a10513a7bed79f475b6726839150c461ce1ab08176d67c6ac6687e2dde5d897c9fda416b39d9
n2 = 0x00a9a94e2d326f482636e93f8b70708d1ca6240168f91b833dd1ff5fd1760c220b9ca6e1ee009feb718f81a4aeb382a2f093576d801ace54984a8ed66b032a352a6c8d8f32e06a98a42135b8c5a77a3f1a3edd22349a35cfcd7caa9cb18d8d4a0e9bd730119eeb6634f7b791d6519e187e747f0b5086143491c6b419e8713e8d2550bd82899652bb5e951b75e1da4efbcf5068ef0f55e853a6a4beca7e049f6bb86e3f7c0066e7e8dc2785aca98a65b45cc7eb587bb94fb210fb8f709d80dc33d1ff7ac093072fdc738d1e12e303fd34c3cd8f530f6aa2abbf66e98106eaad279dfc867bdcd62fe1e2925fd0306f51cf2f320c4dba3ff766da3163e99f971f31453c08a7cae0fc922cde0bbd4b449bab127cdf1d5da6afa082aa80663d4b58bd359949f03285d74880aee5765c6289fd6c856f561d166c051d645f33749c21222a020c8bed4f8e070dbf80b45bb0f12f1f985fedd8e971bd6ce6fab2c078852576199a004dbbbd8da59955784fec04d577c49cbffbb8ea23277dca4770af0b365aa08b972726e5b316ef5c5e1a297f06e9bca586635647d1105f60d562a8f680fede7216c309120dea7f8c237ac602c5d8092bf6e6d54a974857dec098b3287bdf3f91e03f15ab3f189c17e3c10db2b0bc096c1170d2905160e274673ccf0e06ca4e453824bd778685dd32b813b2e9a09e6b371cb6f0369fc6e2247d4239095039

p = GCD(n1, n2)

q1 = n1 // p
q2 = n2 // p

phi1 = (p-1)*(q1-1)
phi2 = (p-1)*(q2-1)

d1 = inverse(e, phi1)
d2 = inverse(e, phi2)

assert pow(pow(777, e, n1), d1, n1) == 777
assert pow(pow(777, e, n2), d2, n2) == 777


privkey1 = RSA.construct( (n1, e, d1, p, q1) )
with open("privkey-1.pem", "wb") as f:
    f.write(privkey1.export_key("PEM"))
    
    
import os
os.system("curl https://psandqs.dangerous-testing.utctf.live/ --key privkey-1.pem --cert cert-chain-1.pem")