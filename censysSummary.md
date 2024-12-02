# CENSYS

This is a Censys tutorial by Jordi Caylà Bayona for his Final Grade Research
## Free Methods
In this paragraph theres all Free Methods usable in Censys library.

## Search( ) method
Search() method is used to perform searches across Censys' dataset and returns multiple results that match the search criteria. 
```diff
+ It's useful when you need to find multiple hosts or certificates that meet certain conditions.
```


### Utilitzation

```
query = h.search("services.port: 443")

# Other utilitzations:

query = h.search("services.service_name: HTTP", per_page=5, pages=2)
```

### Output
```
for page in query:
    for host in page:
        print(host)
```

### Full Output
<details>
<summary>Click to expand code</summary>

```python
# For each host, this is the result:

{
   "location":{
      "postal_code":"20147",
      "province":"Virginia",
      "timezone":"America/New_York",
      "country":"United States",
      "continent":"North America",
      "coordinates":{
         "latitude":39.04372,
         "longitude":-77.48749
      },
      "country_code":"US",
      "city":"Ashburn"
   },
   "last_updated_at":"2024-10-27T17:02:26.140Z",
   "autonomous_system":{
      "description":"AKAMAI-AS",
      "bgp_prefix":"23.4.176.0/20",
      "asn":16625,
      "country_code":"US",
      "name":"AKAMAI-AS"
   },
   "ip":"23.4.189.49",
   "dns":{
      "reverse_dns":{
         "names":[
            "a23-4-189-49.deploy.static.akamaitechnologies.com"
         ]
      }
   },
   "operating_system":{
      "part":"o",
      "vendor":"Akamai",
      "component_uniform_resource_identifiers":[
         
      ],
      "other":[
         {
            "key":"family",
            "value":"Linux"
         },
         {
            "key":"device",
            "value":"Web Proxy"
         }
      ],
      "cpe":"",
      "source":"OSI_APPLICATION_LAYER"
   },
   "services":[
      {
         "transport_protocol":"TCP",
         "extended_service_name":"HTTP",
         "service_name":"HTTP",
         "port":80
      },
      {
         "service_name":"HTTP",
         "transport_protocol":"TCP",
         "certificate":"f58a16fb5ddc40dd90c737cee57bc8bd3587d52bb09eefbc14894dbc4f0af8c8",
         "extended_service_name":"HTTPS",
         "port":443
      }
   ]
}
```
</details>

## View( ) method
View() is designed to get detailed information about a specific item when you already know its identifier (like an IP or certificate hash). It only returns a single result with complete information about that particular item.
```diff
+ It's useful when you want information from an specific host
```


### Utilitzation

```
query = h.view("8.8.8.8")
```

### Output
```
print(query)
```
```
# Simplified output

{
   "ip":"8.8.8.8",
   "services":[],
   "location":{},
   "location_updated_at":"2024-10-16T10:52:05.111121559Z",
   "autonomous_system":{},
   "autonomous_system_updated_at":"2024-10-26T06:33:23.841316556Z",
   "whois":{},
   "dns":{},
   "last_updated_at":"2024-10-27T16:39:12.343Z"
}
```

### Full Output

<details>
<summary>Click to expand code</summary>

```python
{
   "ip":"8.8.8.8",
   "services":[
      {
         "_decoded":"dns",
         "dns":{
            "server_type":"FORWARDING",
            "resolves_correctly":true,
            "answers":[
               {
                  "name":"ip.parrotdns.com.",
                  "response":"35.202.119.40",
                  "type":"A"
               },
               {
                  "name":"ip.parrotdns.com.",
                  "response":"74.125.186.146",
                  "type":"A"
               }
            ],
            "questions":[
               {
                  "name":"ip.parrotdns.com.",
                  "response":";ip.parrotdns.com.\tIN\t A",
                  "type":"A"
               }
            ],
            "edns":{
               "do":true,
               "udp":512,
               "version":0
            },
            "r_code":"SUCCESS"
         },
         "extended_service_name":"DNS",
         "observed_at":"2024-10-27T16:39:11.239145327Z",
         "perspective_id":"PERSPECTIVE_NTT",
         "port":53,
         "service_name":"DNS",
         "source_ip":"206.168.34.199",
         "transport_protocol":"UDP",
         "truncated":false
      },
      {
         "_decoded":"http",
         "_encoding":{
            "banner":"DISPLAY_UTF8",
            "certificate":"DISPLAY_HEX",
            "banner_hex":"DISPLAY_HEX"
         },
         "banner":"HTTP/1.1 302 Found\r\nX-Content-Type-Options: nosniff\r\nAccess-Control-Allow-Origin: *\r\nLocation: https://dns.google/\r\nDate:  <REDACTED>\r\nContent-Type: text/html; charset=UTF-8\r\nServer: HTTP server (unknown)\r\nContent-Length: 216\r\nX-XSS-Protection: 0\r\nX-Frame-Options: SAMEORIGIN\r\nAlt-Svc: h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000\r\n",
         "banner_hashes":[
            "sha256:4437c46b3fe8051471b181c33e3d9a3dc7fb9d41d3e1f1c9ff0e0fc7409b702f"
         ],
         "banner_hex":"485454502f312e312033303220466f756e640d0a582d436f6e74656e742d547970652d4f7074696f6e733a206e6f736e6966660d0a4163636573732d436f6e74726f6c2d416c6c6f772d4f726967696e3a202a0d0a4c6f636174696f6e3a2068747470733a2f2f646e732e676f6f676c652f0d0a446174653a20203c52454441435445443e0d0a436f6e74656e742d547970653a20746578742f68746d6c3b20636861727365743d5554462d380d0a5365727665723a2048545450207365727665722028756e6b6e6f776e290d0a436f6e74656e742d4c656e6774683a203231360d0a582d5853532d50726f74656374696f6e3a20300d0a582d4672616d652d4f7074696f6e733a2053414d454f524947494e0d0a416c742d5376633a2068333d223a343433223b206d613d323539323030302c68332d32393d223a343433223b206d613d323539323030300d0a",
         "certificate":"50114f8038389859da7e1f4776bedf0b8d48e0ee302b60623c3a0f51a5d138a8",
         "extended_service_name":"HTTPS",
         "http":{
            "request":{
               "method":"GET",
               "uri":"https://8.8.8.8/",
               "headers":{
                  "User_Agent":[
                     "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)"
                  ],
                  "_encoding":{
                     "User_Agent":"DISPLAY_UTF8",
                     "Accept":"DISPLAY_UTF8"
                  },
                  "Accept":[
                     "*/*"
                  ]
               }
            },
            "response":{
               "protocol":"HTTP/1.1",
               "status_code":302,
               "status_reason":"Found",
               "headers":{
                  "X_Frame_Options":[
                     "SAMEORIGIN"
                  ],
                  "_encoding":{
                     "X_Frame_Options":"DISPLAY_UTF8",
                     "Server":"DISPLAY_UTF8",
                     "Content_Length":"DISPLAY_UTF8",
                     "Content_Type":"DISPLAY_UTF8",
                     "Location":"DISPLAY_UTF8",
                     "X_XSS_Protection":"DISPLAY_UTF8",
                     "Access_Control_Allow_Origin":"DISPLAY_UTF8",
                     "X_Content_Type_Options":"DISPLAY_UTF8",
                     "Date":"DISPLAY_UTF8",
                     "Alt_Svc":"DISPLAY_UTF8"
                  },
                  "Server":[
                     "HTTP server (unknown)"
                  ],
                  "Content_Length":[
                     "216"
                  ],
                  "Content_Type":[
                     "text/html; charset=UTF-8"
                  ],
                  "Location":[
                     "https://dns.google/"
                  ],
                  "X_XSS_Protection":[
                     "0"
                  ],
                  "Access_Control_Allow_Origin":[
                     "*"
                  ],
                  "X_Content_Type_Options":[
                     "nosniff"
                  ],
                  "Date":[
                     "<REDACTED>"
                  ],
                  "Alt_Svc":[
                     "h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000"
                  ]
               },
               "_encoding":{
                  "html_tags":"DISPLAY_UTF8",
                  "body":"DISPLAY_UTF8",
                  "body_hash":"DISPLAY_UTF8",
                  "html_title":"DISPLAY_UTF8"
               },
               "html_tags":[
                  "<TITLE>302 Moved</TITLE>",
                  "<meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">"
               ],
               "body_size":216,
               "body":"<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\n<TITLE>302 Moved</TITLE></HEAD><BODY>\n<H1>302 Moved</H1>\nThe document has moved\n<A HREF=\"https://dns.google/\">here</A>.\r\n</BODY></HTML>\r\n",
               "body_hashes":[
                  "sha256:4d2df97f002e1d1905cf64366eddaa9a57f2f99b3cc7101c3bebff18428ed894",
                  "sha1:1fd84b37b709256752fe1f865f86b5bec05cf712"
               ],
               "body_hash":"sha1:1fd84b37b709256752fe1f865f86b5bec05cf712",
               "html_title":"302 Moved"
            },
            "supports_http2":true
         },
         "jarm":{
            "_encoding":{
               "fingerprint":"DISPLAY_HEX",
               "cipher_and_version_fingerprint":"DISPLAY_HEX",
               "tls_extensions_sha256":"DISPLAY_HEX"
            },
            "fingerprint":"29d3fd00029d29d00042d43d00041d598ac0c1012db967bb1ad0ff2491b3ae",
            "cipher_and_version_fingerprint":"29d3fd00029d29d00042d43d00041d",
            "tls_extensions_sha256":"598ac0c1012db967bb1ad0ff2491b3ae",
            "observed_at":"2024-10-25T16:54:22.765110158Z"
         },
         "observed_at":"2024-10-27T14:44:01.811676766Z",
         "perspective_id":"PERSPECTIVE_HE",
         "port":443,
         "service_name":"HTTP",
         "source_ip":"162.142.125.223",
         "tls":{
            "version_selected":"TLSv1_3",
            "cipher_selected":"TLS_CHACHA20_POLY1305_SHA256",
            "certificates":{
               "_encoding":{
                  "leaf_fp_sha_256":"DISPLAY_HEX",
                  "chain_fps_sha_256":"DISPLAY_HEX"
               },
               "leaf_fp_sha_256":"50114f8038389859da7e1f4776bedf0b8d48e0ee302b60623c3a0f51a5d138a8",
               "chain_fps_sha_256":[
                  "e6fe22bf45e4f0d3b85c59e02c0f495418e1eb8d3210f788d48cd5e1cb547cd4",
                  "3ee0278df71fa3c125c4cd487f01d774694e6fc57e0cd94c24efd769133918e5"
               ],
               "leaf_data":{
                  "names":[
                     "*.dns.google.com",
                     "8.8.4.4",
                     "8.8.8.8",
                     "8888.google",
                     "dns.google",
                     "dns.google.com",
                     "dns64.dns.google"
                  ],
                  "subject_dn":"CN=dns.google",
                  "issuer_dn":"C=US, O=Google Trust Services, CN=WR2",
                  "pubkey_bit_size":2048,
                  "pubkey_algorithm":"RSA",
                  "tbs_fingerprint":"0870d921e222e7bbb309784caf83519c339a4cd2dd575636e587ac927218298c",
                  "fingerprint":"50114f8038389859da7e1f4776bedf0b8d48e0ee302b60623c3a0f51a5d138a8",
                  "issuer":{
                     "common_name":[
                        "WR2"
                     ],
                     "organization":[
                        "Google Trust Services"
                     ],
                     "country":[
                        "US"
                     ]
                  },
                  "subject":{
                     "common_name":[
                        "dns.google"
                     ]
                  },
                  "public_key":{
                     "key_algorithm":"RSA",
                     "rsa":{
                        "_encoding":{
                           "modulus":"DISPLAY_BASE64",
                           "exponent":"DISPLAY_BASE64"
                        },
                        "modulus":"5HstIa1PYNmBX23ZIRBnHnBoSUS2ruGvYACpHpZVDVRaPhONiN5XSg3+L67gscPc2FafO8qDLa87uiwX1qEuLfSr1YvECan35PW0tG/J065YPdvEHT2fe2q6koTJyIUaHNhsTnw1RrIGIMQpftczVswy2QjvUh1NLnHopAEQ9q9aEBhtfSqgXYkIPiSatzx4YVD4X+h/JLV/r2OtXa/Bdnw3w6vXI2l6c7tkQmMmMxTWYtkZ68hxV+XNiqzJpRs7PKQQjmK09Vyf6xp85M4GaY4P4IsWeUwC6G5PE1q9W5XB/+kg+Mv1w1yTuatYWRlLp4rs+wUdWaqZjEuwJHmUlQ==",
                        "exponent":"AAEAAQ==",
                        "length":256
                     },
                     "fingerprint":"fb1dd79a7780b3a8fcf3ba77cc65c507fcfcd8bd4e008846c89b2e748585351c"
                  },
                  "signature":{
                     "signature_algorithm":"SHA256-RSA",
                     "self_signed":false
                  }
               },
               "chain":[
                  {
                     "fingerprint":"e6fe22bf45e4f0d3b85c59e02c0f495418e1eb8d3210f788d48cd5e1cb547cd4",
                     "subject_dn":"C=US, O=Google Trust Services, CN=WR2",
                     "issuer_dn":"C=US, O=Google Trust Services LLC, CN=GTS Root R1"
                  },
                  {
                     "fingerprint":"3ee0278df71fa3c125c4cd487f01d774694e6fc57e0cd94c24efd769133918e5",
                     "subject_dn":"C=US, O=Google Trust Services LLC, CN=GTS Root R1",
                     "issuer_dn":"C=BE, O=GlobalSign nv-sa, OU=Root CA, CN=GlobalSign Root CA"
                  }
               ]
            },
            "_encoding":{
               "ja3s":"DISPLAY_HEX"
            },
            "ja3s":"d75f9129bb5d05492a65ff78e081bcb2",
            "ja4s":"t130200_1303_234ea6891581",
            "versions":[
               {
                  "tls_version":"TLSv1_3",
                  "_encoding":{
                     "ja3s":"DISPLAY_HEX"
                  },
                  "ja3s":"d75f9129bb5d05492a65ff78e081bcb2",
                  "ja4s":"t130200_1303_234ea6891581"
               },
               {
                  "tls_version":"TLSv1_2",
                  "_encoding":{
                     "ja3s":"DISPLAY_HEX"
                  },
                  "ja3s":"d25619cb77d3219fc9fc14cb6b35eacc",
                  "ja4s":"t120200_cca8_344b4dce5a52"
               }
            ]
         },
         "transport_protocol":"TCP",
         "truncated":false
      },
      {
         "_decoded":"banner_grab",
         "_encoding":{
            "banner":"DISPLAY_UTF8"
         },
         "banner":"",
         "banner_hashes":[
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
         ],
         "extended_service_name":"UNKNOWN",
         "observed_at":"2024-10-26T01:59:34.291572560Z",
         "perspective_id":"PERSPECTIVE_HE",
         "port":443,
         "service_name":"UNKNOWN",
         "source_ip":"162.142.125.195",
         "transport_fingerprint":{
            "quic":{
               "versions":[
                  1,
                  4278190109,
                  1362113840,
                  176863754,
                  1362113590,
                  1362113587
               ]
            }
         },
         "transport_protocol":"QUIC",
         "truncated":false
      },
      {
         "_decoded":"banner_grab",
         "_encoding":{
            "banner":"DISPLAY_UTF8",
            "certificate":"DISPLAY_HEX"
         },
         "banner":"",
         "banner_hashes":[
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
         ],
         "certificate":"50114f8038389859da7e1f4776bedf0b8d48e0ee302b60623c3a0f51a5d138a8",
         "extended_service_name":"UNKNOWN",
         "jarm":{
            "_encoding":{
               "fingerprint":"DISPLAY_HEX",
               "cipher_and_version_fingerprint":"DISPLAY_HEX",
               "tls_extensions_sha256":"DISPLAY_HEX"
            },
            "fingerprint":"29d3fd00029d29d00042d43d00041df6ab62833359bd21fbf27287504787f8",
            "cipher_and_version_fingerprint":"29d3fd00029d29d00042d43d00041d",
            "tls_extensions_sha256":"f6ab62833359bd21fbf27287504787f8",
            "observed_at":"2024-10-27T01:39:03.160240104Z"
         },
         "observed_at":"2024-10-26T19:07:29.874285840Z",
         "perspective_id":"PERSPECTIVE_NTT",
         "port":853,
         "service_name":"UNKNOWN",
         "source_ip":"206.168.34.33",
         "tls":{
            "version_selected":"TLSv1_3",
            "cipher_selected":"TLS_CHACHA20_POLY1305_SHA256",
            "certificates":{
               "_encoding":{
                  "leaf_fp_sha_256":"DISPLAY_HEX",
                  "chain_fps_sha_256":"DISPLAY_HEX"
               },
               "leaf_fp_sha_256":"50114f8038389859da7e1f4776bedf0b8d48e0ee302b60623c3a0f51a5d138a8",
               "chain_fps_sha_256":[
                  "e6fe22bf45e4f0d3b85c59e02c0f495418e1eb8d3210f788d48cd5e1cb547cd4",
                  "3ee0278df71fa3c125c4cd487f01d774694e6fc57e0cd94c24efd769133918e5"
               ],
               "leaf_data":{
                  "names":[
                     "*.dns.google.com",
                     "8.8.4.4",
                     "8.8.8.8",
                     "8888.google",
                     "dns.google",
                     "dns.google.com",
                     "dns64.dns.google"
                  ],
                  "subject_dn":"CN=dns.google",
                  "issuer_dn":"C=US, O=Google Trust Services, CN=WR2",
                  "pubkey_bit_size":2048,
                  "pubkey_algorithm":"RSA",
                  "tbs_fingerprint":"0870d921e222e7bbb309784caf83519c339a4cd2dd575636e587ac927218298c",
                  "fingerprint":"50114f8038389859da7e1f4776bedf0b8d48e0ee302b60623c3a0f51a5d138a8",
                  "issuer":{
                     "common_name":[
                        "WR2"
                     ],
                     "organization":[
                        "Google Trust Services"
                     ],
                     "country":[
                        "US"
                     ]
                  },
                  "subject":{
                     "common_name":[
                        "dns.google"
                     ]
                  },
                  "public_key":{
                     "key_algorithm":"RSA",
                     "rsa":{
                        "_encoding":{
                           "modulus":"DISPLAY_BASE64",
                           "exponent":"DISPLAY_BASE64"
                        },
                        "modulus":"5HstIa1PYNmBX23ZIRBnHnBoSUS2ruGvYACpHpZVDVRaPhONiN5XSg3+L67gscPc2FafO8qDLa87uiwX1qEuLfSr1YvECan35PW0tG/J065YPdvEHT2fe2q6koTJyIUaHNhsTnw1RrIGIMQpftczVswy2QjvUh1NLnHopAEQ9q9aEBhtfSqgXYkIPiSatzx4YVD4X+h/JLV/r2OtXa/Bdnw3w6vXI2l6c7tkQmMmMxTWYtkZ68hxV+XNiqzJpRs7PKQQjmK09Vyf6xp85M4GaY4P4IsWeUwC6G5PE1q9W5XB/+kg+Mv1w1yTuatYWRlLp4rs+wUdWaqZjEuwJHmUlQ==",
                        "exponent":"AAEAAQ==",
                        "length":256
                     },
                     "fingerprint":"fb1dd79a7780b3a8fcf3ba77cc65c507fcfcd8bd4e008846c89b2e748585351c"
                  },
                  "signature":{
                     "signature_algorithm":"SHA256-RSA",
                     "self_signed":false
                  }
               },
               "chain":[
                  {
                     "fingerprint":"e6fe22bf45e4f0d3b85c59e02c0f495418e1eb8d3210f788d48cd5e1cb547cd4",
                     "subject_dn":"C=US, O=Google Trust Services, CN=WR2",
                     "issuer_dn":"C=US, O=Google Trust Services LLC, CN=GTS Root R1"
                  },
                  {
                     "fingerprint":"3ee0278df71fa3c125c4cd487f01d774694e6fc57e0cd94c24efd769133918e5",
                     "subject_dn":"C=US, O=Google Trust Services LLC, CN=GTS Root R1",
                     "issuer_dn":"C=BE, O=GlobalSign nv-sa, OU=Root CA, CN=GlobalSign Root CA"
                  }
               ]
            },
            "_encoding":{
               "ja3s":"DISPLAY_HEX"
            },
            "ja3s":"d75f9129bb5d05492a65ff78e081bcb2",
            "ja4s":"t130200_1303_234ea6891581",
            "versions":[
               {
                  "tls_version":"TLSv1_3",
                  "_encoding":{
                     "ja3s":"DISPLAY_HEX"
                  },
                  "ja3s":"d75f9129bb5d05492a65ff78e081bcb2",
                  "ja4s":"t130200_1303_234ea6891581"
               },
               {
                  "tls_version":"TLSv1_2",
                  "_encoding":{
                     "ja3s":"DISPLAY_HEX"
                  },
                  "ja3s":"d25619cb77d3219fc9fc14cb6b35eacc",
                  "ja4s":"t120200_cca8_344b4dce5a52"
               }
            ]
         },
         "transport_protocol":"TCP",
         "truncated":false
      }
   ],
   "location":{
      "continent":"North America",
      "country":"United States",
      "country_code":"US",
      "city":"Mountain View",
      "postal_code":"94043",
      "timezone":"America/Los_Angeles",
      "province":"California",
      "coordinates":{
         "latitude":37.4056,
         "longitude":-122.0775
      }
   },
   "location_updated_at":"2024-10-16T10:52:05.111121559Z",
   "autonomous_system":{
      "asn":15169,
      "description":"GOOGLE",
      "bgp_prefix":"8.8.8.0/24",
      "name":"GOOGLE",
      "country_code":"US"
   },
   "autonomous_system_updated_at":"2024-10-26T06:33:23.841316556Z",
   "whois":{
      "network":{
         "handle":"GOGL",
         "name":"Google LLC",
         "cidrs":[
            "8.8.8.0/24"
         ],
         "created":"2023-12-28T00:00:00Z",
         "updated":"2023-12-28T00:00:00Z",
         "allocation_type":"ALLOCATION"
      },
      "organization":{
         "handle":"GOGL",
         "name":"Google LLC",
         "street":"1600 Amphitheatre Parkway",
         "city":"Mountain View",
         "state":"CA",
         "postal_code":"94043",
         "country":"US",
         "abuse_contacts":[
            {
               "handle":"ABUSE5250-ARIN",
               "name":"Abuse",
               "email":"network-abuse@google.com"
            }
         ],
         "admin_contacts":[
            {
               "handle":"ZG39-ARIN",
               "name":"Google LLC",
               "email":"arin-contact@google.com"
            }
         ],
         "tech_contacts":[
            {
               "handle":"ZG39-ARIN",
               "name":"Google LLC",
               "email":"arin-contact@google.com"
            }
         ]
      }
   },
   "dns":{
      "names":[
         "cdnssl.imaage.win",
         "primeemaill.com",
         "anker34.de",
         "ceezoo.com",
         "auth.us-west-2.prod.veriatolabs.com",
         "prod.rialtic.app",
         "yourserverpromo.de",
         "bellydancejoy.com",
         "lookgood.synology.me",
         "bru3d.com",
         "treatlife.cn",
         "auth.techenablement.awspartner.com",
         "www.carpediem.je",
         "kyoto.bretagnesaintmalo.com",
         "ioh.me",
         "test.data-lake-dev.bainnonprod.com",
         "haoyue18.com",
         "buscamosadios.com",
         "geratest63.brownbearcentral.com",
         "jtest6.brownbearcentral.com",
         "armsworx.com",
         "shwu.me",
         "batuketu.com",
         "sigmainternacional.com",
         "www.bellydancejoy.com",
         "www.enveeshop.com",
         "www.apcoworldwde.com",
         "alucitra.com",
         "besterfasteners.com",
         "mail.ankaraasfalt.com",
         "geratest65.brownbearcentral.com",
         "atlantis.axa-altitude.com",
         "cdvdrip.com",
         "anscln.gdcsoluciones.com",
         "www.busticati.com",
         "yun.ayakasuki.com",
         "www.bensluxury.com",
         "servers.banahosting.com",
         "tlounge6.wubbalubba.com",
         "deltajobseurope.com",
         "www.go4web.se",
         "0310.fun",
         "anandhardware.com",
         "v66u.website",
         "autodiscover.arabgaspetroleum.com",
         "wadiyun.cc",
         "unmannedtechs.com",
         "sr-legal.com.my",
         "mail.ccddns.com",
         "test.cabinetchaubet.com",
         "059879e5-b2e8-4f58-aa46-95f69d92aa34.random.beyeuvn.com",
         "cidr-truth-prod.cloud.bayer.com",
         "bisskapp.co.nz",
         "argentustravel.com",
         "dev.andi-copilot.com",
         "icshit.in",
         "www.belovebikini.com",
         "test.bazissoft.com",
         "bfqcl01.com",
         "portalscloud.us",
         "mail.all-service.in.ua",
         "mattneef.people.aws.dev",
         "auth.eu-west-1.prod.veriatolabs.com",
         "berchmark.com",
         "gr7.sport-wire.com",
         "bandwagonhoster.com",
         "www.danielxu1981.net",
         "tbag.line.pm",
         "www.liangel.top",
         "awesomewaterbeds.com",
         "huayiyi.ai",
         "s15b.us",
         "atlantis.dev.axa-altitude.com",
         "data.52daishu.life",
         "apthscaws.com",
         "upload.cadvect.com",
         "www.imluck.vip",
         "cenreceptoria.com",
         "arbeitskrafte-polen.com",
         "prod.clt.choreoapps.dev",
         "api.ec-cs.hellolori.com",
         "cpanel.arabgaspetroleum.com",
         "mail.dpai.ma",
         "hamzah.tik.my.id",
         "www.batuketu.com",
         "policycheck.chisel.ai",
         "www.haoyue18.com",
         "www.ayakasuki.com",
         "belovebikini.com",
         "2c8b3f19-0325-4acc-a3dd-31a918e4dbf5.random.visitenkartenschachteln.de",
         "admin.newsquake.com.au",
         "d7z7of5iv7gtc2kw.test.support.newrelic.com",
         "dev.utnhimypham.com",
         "blockchainnrecovery.com",
         "identity.msbe.cie.ac",
         "xuekao.online",
         "tttggt.com",
         "atlantis.int.axa-altitude.com",
         "www.unangbuongtrung.com.vn",
         "paces-test.dhcs.ca.gov"
      ],
      "records":{
         "bisskapp.co.nz":{
            "record_type":"A",
            "resolved_at":"2024-10-23T23:45:53.703999779Z"
         },
         "bru3d.com":{
            "record_type":"A",
            "resolved_at":"2024-10-18T14:35:23.702271622Z"
         },
         "argentustravel.com":{
            "record_type":"A",
            "resolved_at":"2024-10-25T15:07:46.683210755Z"
         },
         "0310.fun":{
            "record_type":"A",
            "resolved_at":"2024-10-19T20:27:53.523785528Z"
         },
         "primeemaill.com":{
            "record_type":"A",
            "resolved_at":"2024-10-14T16:28:40.656385762Z"
         },
         "besterfasteners.com":{
            "record_type":"A",
            "resolved_at":"2024-10-17T15:06:54.516688728Z"
         },
         "auth.eu-west-1.prod.veriatolabs.com":{
            "record_type":"A",
            "resolved_at":"2024-10-25T19:12:45.382390582Z"
         },
         "d7z7of5iv7gtc2kw.test.support.newrelic.com":{
            "record_type":"A",
            "resolved_at":"2024-10-12T16:17:59.226116085Z"
         },
         "test.cabinetchaubet.com":{
            "record_type":"A",
            "resolved_at":"2024-10-20T15:34:18.181110442Z"
         },
         "treatlife.cn":{
            "record_type":"A",
            "resolved_at":"2024-10-17T13:18:37.237711803Z"
         },
         "xuekao.online":{
            "record_type":"A",
            "resolved_at":"2024-10-11T22:29:26.902971633Z"
         },
         "www.liangel.top":{
            "record_type":"A",
            "resolved_at":"2024-10-24T08:47:48.921540331Z"
         },
         "auth.techenablement.awspartner.com":{
            "record_type":"A",
            "resolved_at":"2024-10-21T14:50:59.186079005Z"
         },
         "icshit.in":{
            "record_type":"A",
            "resolved_at":"2024-10-15T20:52:23.720967623Z"
         },
         "www.apcoworldwde.com":{
            "record_type":"CNAME",
            "resolved_at":"2024-10-20T14:58:31.702345041Z"
         },
         "ceezoo.com":{
            "record_type":"A",
            "resolved_at":"2024-10-25T15:40:07.602517093Z"
         },
         "tlounge6.wubbalubba.com":{
            "record_type":"A",
            "resolved_at":"2024-10-19T19:02:12.647395996Z"
         },
         "alucitra.com":{
            "record_type":"A",
            "resolved_at":"2024-09-20T13:01:44.410514518Z"
         },
         "haoyue18.com":{
            "record_type":"A",
            "resolved_at":"2024-10-21T16:27:29.189764763Z"
         },
         "arbeitskrafte-polen.com":{
            "record_type":"A",
            "resolved_at":"2024-10-27T14:54:18.665062202Z"
         },
         "059879e5-b2e8-4f58-aa46-95f69d92aa34.random.beyeuvn.com":{
            "record_type":"A",
            "resolved_at":"2024-10-23T14:52:58.730558244Z"
         },
         "cidr-truth-prod.cloud.bayer.com":{
            "record_type":"A",
            "resolved_at":"2024-09-27T15:33:26.768877200Z"
         },
         "www.ayakasuki.com":{
            "record_type":"A",
            "resolved_at":"2024-09-23T14:32:56.579547811Z"
         },
         "sigmainternacional.com":{
            "record_type":"A",
            "resolved_at":"2024-10-01T17:48:34.718096973Z"
         },
         "dev.andi-copilot.com":{
            "record_type":"A",
            "resolved_at":"2024-10-25T15:04:00.379444398Z"
         },
         "anandhardware.com":{
            "record_type":"A",
            "resolved_at":"2024-10-26T14:28:27.735926530Z"
         },
         "atlantis.int.axa-altitude.com":{
            "record_type":"A",
            "resolved_at":"2024-10-26T14:33:35.434435981Z"
         },
         "apthscaws.com":{
            "record_type":"A",
            "resolved_at":"2024-10-24T14:35:43.824376742Z"
         },
         "servers.banahosting.com":{
            "record_type":"A",
            "resolved_at":"2024-10-17T15:04:43.543985114Z"
         },
         "v66u.website":{
            "record_type":"A",
            "resolved_at":"2024-09-17T01:02:07.806713358Z"
         },
         "www.danielxu1981.net":{
            "record_type":"A",
            "resolved_at":"2024-10-23T22:21:06.416733084Z"
         },
         "anscln.gdcsoluciones.com":{
            "record_type":"A",
            "resolved_at":"2024-10-17T16:05:43.651508041Z"
         },
         "cdvdrip.com":{
            "record_type":"A",
            "resolved_at":"2024-10-24T15:17:03.652700391Z"
         },
         "www.batuketu.com":{
            "record_type":"CNAME",
            "resolved_at":"2024-10-19T15:07:05.101521113Z"
         },
         "mail.ankaraasfalt.com":{
            "record_type":"CNAME",
            "resolved_at":"2024-10-23T14:28:10.181594088Z"
         },
         "cpanel.arabgaspetroleum.com":{
            "record_type":"A",
            "resolved_at":"2024-10-24T14:32:19.955010597Z"
         },
         "sr-legal.com.my":{
            "record_type":"A",
            "resolved_at":"2024-10-12T20:00:02.318427775Z"
         },
         "yourserverpromo.de":{
            "record_type":"A",
            "resolved_at":"2024-10-07T17:21:59.125554112Z"
         },
         "lookgood.synology.me":{
            "record_type":"A",
            "resolved_at":"2024-09-19T20:14:16.691226060Z"
         },
         "wadiyun.cc":{
            "record_type":"A",
            "resolved_at":"2024-09-27T13:04:16.142464007Z"
         },
         "portalscloud.us":{
            "record_type":"A",
            "resolved_at":"2024-10-06T01:03:58.037670489Z"
         },
         "atlantis.dev.axa-altitude.com":{
            "record_type":"A",
            "resolved_at":"2024-10-15T14:53:23.895265843Z"
         },
         "kyoto.bretagnesaintmalo.com":{
            "record_type":"A",
            "resolved_at":"2024-10-23T14:56:56.667663973Z"
         },
         "cdnssl.imaage.win":{
            "record_type":"A",
            "resolved_at":"2024-10-06T01:08:41.913076294Z"
         },
         "paces-test.dhcs.ca.gov":{
            "record_type":"A",
            "resolved_at":"2024-10-15T20:39:42.462405792Z"
         },
         "tttggt.com":{
            "record_type":"A",
            "resolved_at":"2024-10-17T18:18:19.370121007Z"
         },
         "www.busticati.com":{
            "record_type":"A",
            "resolved_at":"2024-10-21T15:21:26.150876279Z"
         },
         "mattneef.people.aws.dev":{
            "record_type":"A",
            "resolved_at":"2024-10-15T20:01:02.501558023Z"
         },
         "awesomewaterbeds.com":{
            "record_type":"A",
            "resolved_at":"2024-10-24T14:37:40.486271329Z"
         },
         "cenreceptoria.com":{
            "record_type":"A",
            "resolved_at":"2024-09-30T14:46:06.040119126Z"
         },
         "ioh.me":{
            "record_type":"A",
            "resolved_at":"2024-10-25T22:04:22.414062112Z"
         },
         "upload.cadvect.com":{
            "record_type":"A",
            "resolved_at":"2024-10-22T15:14:49.758119624Z"
         },
         "anker34.de":{
            "record_type":"CNAME",
            "resolved_at":"2024-10-12T17:46:31.013139013Z"
         },
         "armsworx.com":{
            "record_type":"A",
            "resolved_at":"2024-10-13T15:00:31.476664915Z"
         },
         "bfqcl01.com":{
            "record_type":"A",
            "resolved_at":"2024-10-22T15:07:17.783309300Z"
         },
         "test.bazissoft.com":{
            "record_type":"A",
            "resolved_at":"2024-10-02T15:22:19.781744512Z"
         },
         "geratest65.brownbearcentral.com":{
            "record_type":"A",
            "resolved_at":"2024-10-22T15:11:37.972596985Z"
         },
         "dev.utnhimypham.com":{
            "record_type":"A",
            "resolved_at":"2024-10-18T17:20:18.156784904Z"
         },
         "shwu.me":{
            "record_type":"A",
            "resolved_at":"2024-10-10T21:12:29.970504062Z"
         },
         "mail.dpai.ma":{
            "record_type":"CNAME",
            "resolved_at":"2024-10-24T21:44:04.202263841Z"
         },
         "yun.ayakasuki.com":{
            "record_type":"A",
            "resolved_at":"2024-09-18T13:54:44.840998300Z"
         },
         "policycheck.chisel.ai":{
            "record_type":"A",
            "resolved_at":"2024-10-20T12:18:58.963674738Z"
         },
         "admin.newsquake.com.au":{
            "record_type":"A",
            "resolved_at":"2024-10-25T07:14:50.033863252Z"
         },
         "geratest63.brownbearcentral.com":{
            "record_type":"A",
            "resolved_at":"2024-10-15T15:21:13.137302761Z"
         },
         "auth.us-west-2.prod.veriatolabs.com":{
            "record_type":"A",
            "resolved_at":"2024-10-10T18:19:01.530638319Z"
         },
         "www.belovebikini.com":{
            "record_type":"A",
            "resolved_at":"2024-10-18T14:30:53.717615900Z"
         },
         "gr7.sport-wire.com":{
            "record_type":"A",
            "resolved_at":"2024-10-26T18:02:18.725368355Z"
         },
         "unmannedtechs.com":{
            "record_type":"A",
            "resolved_at":"2024-10-16T17:36:55.856503166Z"
         },
         "prod.clt.choreoapps.dev":{
            "record_type":"A",
            "resolved_at":"2024-10-15T20:01:39.126126747Z"
         },
         "data.52daishu.life":{
            "record_type":"A",
            "resolved_at":"2024-10-04T22:26:54.289031504Z"
         },
         "bellydancejoy.com":{
            "record_type":"A",
            "resolved_at":"2024-10-27T15:22:45.991912513Z"
         },
         "belovebikini.com":{
            "record_type":"A",
            "resolved_at":"2024-10-03T14:26:01.594220627Z"
         },
         "www.unangbuongtrung.com.vn":{
            "record_type":"A",
            "resolved_at":"2024-10-01T01:00:44.241624983Z"
         },
         "www.carpediem.je":{
            "record_type":"A",
            "resolved_at":"2024-10-14T19:13:22.862271041Z"
         },
         "bandwagonhoster.com":{
            "record_type":"CNAME",
            "resolved_at":"2024-10-22T15:04:16.100570994Z"
         },
         "atlantis.axa-altitude.com":{
            "record_type":"A",
            "resolved_at":"2024-10-27T14:59:30.900622064Z"
         },
         "identity.msbe.cie.ac":{
            "record_type":"A",
            "resolved_at":"2024-10-23T12:17:30.760772876Z"
         },
         "tbag.line.pm":{
            "record_type":"A",
            "resolved_at":"2024-10-15T15:12:36.418099178Z"
         },
         "api.ec-cs.hellolori.com":{
            "record_type":"A",
            "resolved_at":"2024-10-25T16:54:08.356147053Z"
         },
         "deltajobseurope.com":{
            "record_type":"A",
            "resolved_at":"2024-10-24T15:36:27.681798757Z"
         },
         "www.imluck.vip":{
            "record_type":"A",
            "resolved_at":"2024-10-14T03:21:19.755394010Z"
         },
         "mail.all-service.in.ua":{
            "record_type":"A",
            "resolved_at":"2024-10-03T03:13:56.120719348Z"
         },
         "www.enveeshop.com":{
            "record_type":"A",
            "resolved_at":"2024-10-14T15:18:48.874139502Z"
         },
         "buscamosadios.com":{
            "record_type":"A",
            "resolved_at":"2024-10-02T15:31:06.368261470Z"
         },
         "www.haoyue18.com":{
            "record_type":"A",
            "resolved_at":"2024-10-20T16:45:32.579832900Z"
         },
         "2c8b3f19-0325-4acc-a3dd-31a918e4dbf5.random.visitenkartenschachteln.de":{
            "record_type":"A",
            "resolved_at":"2024-10-16T18:08:15.977422820Z"
         },
         "www.bensluxury.com":{
            "record_type":"CNAME",
            "resolved_at":"2024-10-15T15:15:35.470766322Z"
         },
         "huayiyi.ai":{
            "record_type":"A",
            "resolved_at":"2024-10-08T12:15:40.968542868Z"
         },
         "autodiscover.arabgaspetroleum.com":{
            "record_type":"A",
            "resolved_at":"2024-10-27T14:54:03.534670489Z"
         },
         "mail.ccddns.com":{
            "record_type":"A",
            "resolved_at":"2024-10-11T15:04:17.792892913Z"
         },
         "blockchainnrecovery.com":{
            "record_type":"A",
            "resolved_at":"2024-10-11T14:57:13.507285865Z"
         },
         "www.bellydancejoy.com":{
            "record_type":"A",
            "resolved_at":"2024-10-16T14:37:51.517464347Z"
         },
         "hamzah.tik.my.id":{
            "record_type":"A",
            "resolved_at":"2024-10-15T20:47:57.203856320Z"
         },
         "jtest6.brownbearcentral.com":{
            "record_type":"A",
            "resolved_at":"2024-10-09T14:42:02.635049137Z"
         },
         "berchmark.com":{
            "record_type":"A",
            "resolved_at":"2024-10-27T15:24:01.864262455Z"
         },
         "prod.rialtic.app":{
            "record_type":"A",
            "resolved_at":"2024-10-27T12:19:33.667770232Z"
         },
         "batuketu.com":{
            "record_type":"A",
            "resolved_at":"2024-10-09T14:37:56.918410008Z"
         },
         "s15b.us":{
            "record_type":"A",
            "resolved_at":"2024-09-17T00:59:52.980018336Z"
         },
         "test.data-lake-dev.bainnonprod.com":{
            "record_type":"A",
            "resolved_at":"2024-10-23T14:50:37.117087951Z"
         },
         "www.go4web.se":{
            "record_type":"A",
            "resolved_at":"2024-10-22T23:20:58.502707585Z"
         }
      },
      "reverse_dns":{
         "names":[
            "dns.google"
         ],
         "resolved_at":"2024-10-23T12:58:14.190469198Z"
      }
   },
   "last_updated_at":"2024-10-27T16:39:12.343Z"
}

```
</details>

## Bulk_view() Method
Bulk_view() is the same as view but with several IPs
```diff
+ It's useful when you want information from various specific host
```


### Utilitzation

```
IPS = [
    "1.1.1.1", 
    "2.2.2.2", 
    "3.3.3.3"
]

hosts = h.bulk_view(IPS)
```

### Output
```
print(hosts)
```

## Aggregate() Method


The aggregate method in the Censys Python library generates a report based on a query and an aggregation field, grouping the data into specified "buckets."

### Utilitzation
```
hosts = h.aggregate(field="services.port", query="8080")
```

### Output 
```
print(hosts)
```
```
{
    "query": "8080",
    "field": "services.port",
    "total": 52276789,
    "duration": 728,
    "total_omitted": 18580801,
    "potential_deviation": 71695,
    "buckets": [
        {
            "key": "8080",
            "count": 6375924
        },
        {
            "key": "80",
            "count": 3558972
        },
        ...
    ]
}
```

## View_host_names() Method
This method shows you it's names (Oh! What a surprise!)

### Utilitzation
```
names = h.view_host_names("1.1.1.1")
```
### Output
```
print(names)
```
```
[
    "0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.5.0.0.0.1.0.3.5.0.c.0.0.0.6.2.ip6.arpa",
    "0.0.0.0.0.0.0.0.0.0.0.e.1.1.0.0.5.0.0.0.1.0.3.5.0.c.0.0.0.6.2.ip6.arpa",
    "0.0.0.0.0.0.0.0.0.0.0.f.2.1.0.0.5.0.0.0.1.0.3.5.0.c.0.0.0.6.2.ip6.arpa",
    "0.0.0.0.0.0.0.d.f.1.0.0.5.0.0.0.1.0.3.5.0.c.0.0.0.6.2.ip6.arpa",
    "0.0.0.0.0.0.0.f.f.1.0.0.5.0.0.0.1.0.3.5.0.c.0.0.0.6.2.ip6.arpa",
    "0.0.0.0.0.0.1.3.4.0.0.5.0.0.0.1.0.3.5.0.c.0.0.0.6.2.ip6.arpa",
    "0.0.5.f.b.f.2.0.6.2.ip6.arpa",
    "0.2.c.1.0.0.5.0.0.0.1.0.3.5.0.c.0.0.0.6.2.ip6.arpa",
    "0.6.b.1.0.0.5.0.0.0.1.0.3.5.0.c.0.0.0.6.2.ip6.arpa",
    "0.99.248.10000.jkelwzwu.f.imtmp.com",
    "0.pizza",
    ...
]
```

## view_host_events() Method
The view_host_events method retrieves events related to a specified host IP, such as changes in observed services or updated metadata. It allows filtering by date range, providing insights into the host's activity over time.

```diff
+ This can be useful for tracking how the services on a host evolve.
```

### Utilitzation
```diff
- In free acounts, you can only query for up to 7 days
```

```
# Define the last 7 days date range
end_time = date.today()
start_time = end_time - timedelta(days=6)

# Query events within the 7-day range
events = h.view_host_events("1.1.1.1", start_time=start_time, end_time=end_time)
```

### Output
```
{
    "ip": "1.1.1.1",
    "events": [
        {
            "timestamp": "2024-10-22T00:10:53.575Z",
            "service_observed": {
                "id": {
                    "port": 80,
                    "service_name": "HTTP",
                    "transport_protocol": "TCP"
                },
                "observed_at": "2024-10-22T00:10:51.391964905Z",
                "perspective_id": "PERSPECTIVE_PCCW",
                "changed_fields": [
                    {
                        "field_name": "http.request.uri"
                    },
                    {
                        "field_name": "http.response.headers.Location.headers"
                    },
                    {
                        "field_name": "http.response.headers.CF-RAY.headers"
                    },
                    {
                        "field_name": "banner"
                    },
                    {
                        "field_name": "banner_hashes"
                    }
                ]
            },
            "_event": "service_observed"
        },
        ...
    ], 
    "links": {
        "next": "AS-RtkfuLIYna5BHFxIXuS5SKcvkhD9r3GS_TWdBymke_ZGHQn_gSuV2HkzkcHIUejxeVcCB_uUAINCmmVR-p4iU7C79WxoMbxANU1HX1TPU9bqOr4TGCdXiG1pJfraTyQAu8rbhO2ezefQKsFaeIW6J2g=="
    }
}
```










## Premium Methods
In this paragraph theres all Premium Methods usable in Censys library.

## Search( )* method
Search method is free, but you cannot use the filtering by fields

### Utilitzation

```
query = h.search(
    "not services.service_name: HTTP",
    per_page=5,
    fields=["ip", "services.port", "services.service_name"],
)
```

### Output
```
censys.common.exceptions.CensysUnauthorizedException: 403 (Forbidden): Your user does not have permission to define specific fields.
```

## view_host_events()* Method
If you are premium, you can query any date ranges
### Utilitzation
```
events = h.view_host_events("1.1.1.1", start_time=date(2022, 1, 1), end_time=date(2022, 1, 31))
print(events)
```
### Output
```
censys.common.exceptions.CensysUnauthorizedException: 403 (Forbidden): Your Censys account only allows for querying historical data for up to 7 days.
```