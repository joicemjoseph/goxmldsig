package dsig

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

const canonicalResponse = `
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://localhost:8080/v1/_saml_callback" ID="id9464273530269711243550013" InResponseTo="_8a64888e-0a14-4fb9-905d-65629b84786a" IssueInstant="2016-03-15T00:21:40.409Z" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exk5zt0r12Edi4rD20h7</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></saml2p:StatusCode></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id9464273531132552093682430" IssueInstant="2016-03-15T00:21:40.409Z" Version="2.0"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exk5zt0r12Edi4rD20h7</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="#id9464273531132552093682430"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>DRYTp4xjc4Ec2+fJkQQ2KxFp/4raYPQYGrLtXTp2IhQ=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>UquJAMHALMZGSab+9XCc6L010djnsDx1wOP7b3LEQpEmGsKUEbblAuI1mdCaKi28VSP7h04S8M4x4xmgG6+RgYERKrMrc6DsW5Mto3nl6TaYQYUMVchp7vX1kDmuGqiEuYusrqIwQnFJNgt+SDAXODolfaJqKH02EMrzEeSFyfEiwaP8+R2jTQ9vqrMTX+t9b9nNo7F1N2sPWFGfk2TC3F5r4H+MF7n33cSny/qzPEEisldLF3LoTdnrPJdKpio/9kPr7ODhks+hwij82gYlvLCXkagmn76lSsAbUgsYoq1C3zvhYUHjTH2c0jmqHNwKT/8FA/oJtxx3N9agDpXEHw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAVLIBhAwMA0GCSqGSIb3DQEBBQUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi0xMTY4MDcxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTYwMjA5MjE1MjA2WhcNMjYwMjA5MjE1MzA2WjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtMTE2ODA3MRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
mtjBOZ8MmhUyi8cGk4dUY6Fj1MFDt/q3FFiaQpLzu3/q5lRVUNUBbAtqQWwY10dzfZguHOuvA5p5
QyiVDvUhe+XkVwN2R2WfArQJRTPnIcOaHrxqQf3o5cCIG21ZtysFHJSo8clPSOe+0VsoRgcJ1aF4
2rODwgqRRZdO9Wh3502XlJ799DJQ23IC7XasKEsGKzJqhlRrfd/FyIuZT0sFHDKRz5snSJhm9gpN
uQlCmk7ONZ1sXqtt+nBIfWIqeoYQubPW7pT5GTc7wouWq4TCjHJiK9k2HiyNxW0E3JX08swEZi2+
LVDjgLzNc4lwjSYIj3AOtPZs8s606oBdIBni4wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBMxSkJ
TxkXxsoKNW0awJNpWRbU81QpheMFfENIzLam4Itc/5kSZAaSy/9e2QKfo4jBo/MMbCq2vM9TyeJQ
DJpRaioUTd2lGh4TLUxAxCxtUk/pascL+3Nn936LFmUCLxaxnbeGzPOXAhscCtU1H0nFsXRnKx5a
cPXYSKFZZZktieSkww2Oi8dg2DYaQhGQMSFMVqgVfwEu4bvCRBvdSiNXdWGCZQmFVzBZZ/9rOLzP
pvTFTPnpkavJm81FLlUhiE/oFgKlCDLWDknSpXAI0uZGERcwPca6xvIMh86LjQKjbVci9FYDStXC
qRnqQ+TccSu/B6uONFsDEngGcXSKfB+a</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">russell.haering@scaleft.com</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="_8a64888e-0a14-4fb9-905d-65629b84786a" NotOnOrAfter="2016-03-15T00:26:40.409Z" Recipient="http://localhost:8080/v1/_saml_callback"></saml2:SubjectConfirmationData></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2016-03-15T00:16:40.409Z" NotOnOrAfter="2016-03-15T00:26:40.409Z"><saml2:AudienceRestriction><saml2:Audience>123</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2016-03-15T00:21:40.409Z" SessionIndex="_8a64888e-0a14-4fb9-905d-65629b84786a"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion></saml2p:Response>`

const canonicalResponse2 = `
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://localhost:8080/v1/_saml_callback" ID="id103532804647787975381325" InResponseTo="_8699c655-c482-451a-9b7f-61668f140b47" IssueInstant="2016-03-16T01:02:57.682Z" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exk5zt0r12Edi4rD20h7</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></saml2p:StatusCode></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id1035328046526588900089424" IssueInstant="2016-03-16T01:02:57.682Z" Version="2.0"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exk5zt0r12Edi4rD20h7</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="#id1035328046526588900089424"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>No1VyQlk8Xif4FiJ+haViwEQySIzBa14lGy0coCn0c8=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>VSV8Vw47q7n/XZwaQOPWQeKI5ZA69fnGZyEFhex4xuaIfC+LOYnfd8q8qcZsm1M6kv47H/dR6YXRIMjPKXZeyX/MKcmGPCadqWFT7EWFvzuO/uy/AB/CL5ZCQiY9H/aOhDysO8glse1S+Y2K0CwvsoRwMfFiO2XOYhVOsngUSkCBdLIB6Oq4f+ZsK0rw/E79n9QUd8owDq3dVC18SFYYdcIVDhQppglyuBEZfu2tG06gD9jls7ZE8vjcMfHmhuHtxlH3ovNLB35NFO/VrCNdFqmD76GnEA98foiJxCX8vzNHF4rPUFXAEdiS4OdQAxb7jNNVoKVYuadunLygysZGSg==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAVLIBhAwMA0GCSqGSIb3DQEBBQUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi0xMTY4MDcxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTYwMjA5MjE1MjA2WhcNMjYwMjA5MjE1MzA2WjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtMTE2ODA3MRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
mtjBOZ8MmhUyi8cGk4dUY6Fj1MFDt/q3FFiaQpLzu3/q5lRVUNUBbAtqQWwY10dzfZguHOuvA5p5
QyiVDvUhe+XkVwN2R2WfArQJRTPnIcOaHrxqQf3o5cCIG21ZtysFHJSo8clPSOe+0VsoRgcJ1aF4
2rODwgqRRZdO9Wh3502XlJ799DJQ23IC7XasKEsGKzJqhlRrfd/FyIuZT0sFHDKRz5snSJhm9gpN
uQlCmk7ONZ1sXqtt+nBIfWIqeoYQubPW7pT5GTc7wouWq4TCjHJiK9k2HiyNxW0E3JX08swEZi2+
LVDjgLzNc4lwjSYIj3AOtPZs8s606oBdIBni4wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBMxSkJ
TxkXxsoKNW0awJNpWRbU81QpheMFfENIzLam4Itc/5kSZAaSy/9e2QKfo4jBo/MMbCq2vM9TyeJQ
DJpRaioUTd2lGh4TLUxAxCxtUk/pascL+3Nn936LFmUCLxaxnbeGzPOXAhscCtU1H0nFsXRnKx5a
cPXYSKFZZZktieSkww2Oi8dg2DYaQhGQMSFMVqgVfwEu4bvCRBvdSiNXdWGCZQmFVzBZZ/9rOLzP
pvTFTPnpkavJm81FLlUhiE/oFgKlCDLWDknSpXAI0uZGERcwPca6xvIMh86LjQKjbVci9FYDStXC
qRnqQ+TccSu/B6uONFsDEngGcXSKfB+a</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">russell.haering@scaleft.com</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="_8699c655-c482-451a-9b7f-61668f140b47" NotOnOrAfter="2016-03-16T01:07:57.682Z" Recipient="http://localhost:8080/v1/_saml_callback"></saml2:SubjectConfirmationData></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2016-03-16T00:57:57.682Z" NotOnOrAfter="2016-03-16T01:07:57.682Z"><saml2:AudienceRestriction><saml2:Audience>123</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2016-03-16T01:02:57.682Z" SessionIndex="_8699c655-c482-451a-9b7f-61668f140b47"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion></saml2p:Response>`

const rawResponse = `
<?xml version="1.0" encoding="UTF-8"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://localhost:8080/v1/_saml_callback" ID="id1619705532971228558789260" InResponseTo="_213843b4-0693-47b8-b2f6-c41e316015cc" IssueInstant="2016-03-22T19:22:57.054Z" Version="2.0" xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exk5zt0r12Edi4rD20h7</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id1619705532971228558789260"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>ijTqmVmDy7ssK+rvmJaCQ6AQaFaXz+HIN/r6O37B0eQ=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>G09fAYXGDLK+/jAekHsNL0RLo40Xm6+VwXmUj0IDIrvIIv/mJU5VD6ylOLnPezLDBVY9BJst1YCz+8krdvmQ8Stkd6qiN2bN/5KpCdika111YGpeNdMmg/E57ZG3S895hTNJQYOfCwhPFUtQuXLkspOaw81pcqOTr+bVSofJ8uQP7cVQa/ANxbjKAj0fhAuxAvZfiqPms5Stv4sNGpzULUDJl87CoEleHExGmpTsI7Qt3EvGToPMZXPHF4MGvuC0Z2ZD4iI6Pr7xk98t54PJtAX2qJu1tZqBJmL0Qcq5spl9W3yC1tAZuDeFLm1C4/T9crO2Q5WILP/tkw/yJ+ZttQ==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAVLIBhAwMA0GCSqGSIb3DQEBBQUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi0xMTY4MDcxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTYwMjA5MjE1MjA2WhcNMjYwMjA5MjE1MzA2WjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtMTE2ODA3MRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
mtjBOZ8MmhUyi8cGk4dUY6Fj1MFDt/q3FFiaQpLzu3/q5lRVUNUBbAtqQWwY10dzfZguHOuvA5p5
QyiVDvUhe+XkVwN2R2WfArQJRTPnIcOaHrxqQf3o5cCIG21ZtysFHJSo8clPSOe+0VsoRgcJ1aF4
2rODwgqRRZdO9Wh3502XlJ799DJQ23IC7XasKEsGKzJqhlRrfd/FyIuZT0sFHDKRz5snSJhm9gpN
uQlCmk7ONZ1sXqtt+nBIfWIqeoYQubPW7pT5GTc7wouWq4TCjHJiK9k2HiyNxW0E3JX08swEZi2+
LVDjgLzNc4lwjSYIj3AOtPZs8s606oBdIBni4wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBMxSkJ
TxkXxsoKNW0awJNpWRbU81QpheMFfENIzLam4Itc/5kSZAaSy/9e2QKfo4jBo/MMbCq2vM9TyeJQ
DJpRaioUTd2lGh4TLUxAxCxtUk/pascL+3Nn936LFmUCLxaxnbeGzPOXAhscCtU1H0nFsXRnKx5a
cPXYSKFZZZktieSkww2Oi8dg2DYaQhGQMSFMVqgVfwEu4bvCRBvdSiNXdWGCZQmFVzBZZ/9rOLzP
pvTFTPnpkavJm81FLlUhiE/oFgKlCDLWDknSpXAI0uZGERcwPca6xvIMh86LjQKjbVci9FYDStXC
qRnqQ+TccSu/B6uONFsDEngGcXSKfB+a</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id16197055330485751495860275" IssueInstant="2016-03-22T19:22:57.054Z" Version="2.0" xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://www.okta.com/exk5zt0r12Edi4rD20h7</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id16197055330485751495860275"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>zln6sheEO2JBdanrT5mZtJZ192tGHavuBpCFHQsJFVg=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>dHh6TWbnjtImyrfjPTX5QzE/6Vm/HsRWVvWWlvFAddf/CvhO4Kc5j8C7hvQoYMLhYuZMFFSReGysuDy5IscOJwTGhhcvb238qHSGGs6q8OUBCsmLSDAbIaGA++LV/tkUZ2ridGIi0yT81UOl1oT1batlHsK3eMyxkpnFmvBzIm4tGTzRkOPpYRLeiM9bxbKI+DM/623DCXyBCLYBzJo1O6QE02aLajwRMi/vmiV4LSiGlFcY9TtDCafdVJRv0tIQ25BQoT4feuHdr6S8xOSpGgRYH5ECamVOt4e079XdEkVUiSzQokiUkgDlTXEyerPLOVsOk4PW5nRs86sXIiGL5w==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAVLIBhAwMA0GCSqGSIb3DQEBBQUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi0xMTY4MDcxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTYwMjA5MjE1MjA2WhcNMjYwMjA5MjE1MzA2WjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtMTE2ODA3MRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
mtjBOZ8MmhUyi8cGk4dUY6Fj1MFDt/q3FFiaQpLzu3/q5lRVUNUBbAtqQWwY10dzfZguHOuvA5p5
QyiVDvUhe+XkVwN2R2WfArQJRTPnIcOaHrxqQf3o5cCIG21ZtysFHJSo8clPSOe+0VsoRgcJ1aF4
2rODwgqRRZdO9Wh3502XlJ799DJQ23IC7XasKEsGKzJqhlRrfd/FyIuZT0sFHDKRz5snSJhm9gpN
uQlCmk7ONZ1sXqtt+nBIfWIqeoYQubPW7pT5GTc7wouWq4TCjHJiK9k2HiyNxW0E3JX08swEZi2+
LVDjgLzNc4lwjSYIj3AOtPZs8s606oBdIBni4wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBMxSkJ
TxkXxsoKNW0awJNpWRbU81QpheMFfENIzLam4Itc/5kSZAaSy/9e2QKfo4jBo/MMbCq2vM9TyeJQ
DJpRaioUTd2lGh4TLUxAxCxtUk/pascL+3Nn936LFmUCLxaxnbeGzPOXAhscCtU1H0nFsXRnKx5a
cPXYSKFZZZktieSkww2Oi8dg2DYaQhGQMSFMVqgVfwEu4bvCRBvdSiNXdWGCZQmFVzBZZ/9rOLzP
pvTFTPnpkavJm81FLlUhiE/oFgKlCDLWDknSpXAI0uZGERcwPca6xvIMh86LjQKjbVci9FYDStXC
qRnqQ+TccSu/B6uONFsDEngGcXSKfB+a</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">phoebe.simon@scaleft.com</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="_213843b4-0693-47b8-b2f6-c41e316015cc" NotOnOrAfter="2016-03-22T19:27:57.054Z" Recipient="http://localhost:8080/v1/_saml_callback"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2016-03-22T19:17:57.054Z" NotOnOrAfter="2016-03-22T19:27:57.054Z" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:AudienceRestriction><saml2:Audience>123</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2016-03-22T19:22:57.054Z" SessionIndex="_213843b4-0693-47b8-b2f6-c41e316015cc" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:Attribute Name="FirstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Phoebe</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="LastName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Simon</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">phoebe.simon@scaleft.com</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion></saml2p:Response>`

const expectedTransformation = `<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://localhost:8080/v1/_saml_callback" ID="id1619705532971228558789260" InResponseTo="_213843b4-0693-47b8-b2f6-c41e316015cc" IssueInstant="2016-03-22T19:22:57.054Z" Version="2.0" xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/exk5zt0r12Edi4rD20h7</saml2:Issuer><saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id16197055330485751495860275" IssueInstant="2016-03-22T19:22:57.054Z" Version="2.0" xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://www.okta.com/exk5zt0r12Edi4rD20h7</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#id16197055330485751495860275"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>zln6sheEO2JBdanrT5mZtJZ192tGHavuBpCFHQsJFVg=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>dHh6TWbnjtImyrfjPTX5QzE/6Vm/HsRWVvWWlvFAddf/CvhO4Kc5j8C7hvQoYMLhYuZMFFSReGysuDy5IscOJwTGhhcvb238qHSGGs6q8OUBCsmLSDAbIaGA++LV/tkUZ2ridGIi0yT81UOl1oT1batlHsK3eMyxkpnFmvBzIm4tGTzRkOPpYRLeiM9bxbKI+DM/623DCXyBCLYBzJo1O6QE02aLajwRMi/vmiV4LSiGlFcY9TtDCafdVJRv0tIQ25BQoT4feuHdr6S8xOSpGgRYH5ECamVOt4e079XdEkVUiSzQokiUkgDlTXEyerPLOVsOk4PW5nRs86sXIiGL5w==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAVLIBhAwMA0GCSqGSIb3DQEBBQUAMIGSMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi0xMTY4MDcxHDAaBgkqhkiG9w0BCQEW
DWluZm9Ab2t0YS5jb20wHhcNMTYwMjA5MjE1MjA2WhcNMjYwMjA5MjE1MzA2WjCBkjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtMTE2ODA3MRwwGgYJ
KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
mtjBOZ8MmhUyi8cGk4dUY6Fj1MFDt/q3FFiaQpLzu3/q5lRVUNUBbAtqQWwY10dzfZguHOuvA5p5
QyiVDvUhe+XkVwN2R2WfArQJRTPnIcOaHrxqQf3o5cCIG21ZtysFHJSo8clPSOe+0VsoRgcJ1aF4
2rODwgqRRZdO9Wh3502XlJ799DJQ23IC7XasKEsGKzJqhlRrfd/FyIuZT0sFHDKRz5snSJhm9gpN
uQlCmk7ONZ1sXqtt+nBIfWIqeoYQubPW7pT5GTc7wouWq4TCjHJiK9k2HiyNxW0E3JX08swEZi2+
LVDjgLzNc4lwjSYIj3AOtPZs8s606oBdIBni4wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBMxSkJ
TxkXxsoKNW0awJNpWRbU81QpheMFfENIzLam4Itc/5kSZAaSy/9e2QKfo4jBo/MMbCq2vM9TyeJQ
DJpRaioUTd2lGh4TLUxAxCxtUk/pascL+3Nn936LFmUCLxaxnbeGzPOXAhscCtU1H0nFsXRnKx5a
cPXYSKFZZZktieSkww2Oi8dg2DYaQhGQMSFMVqgVfwEu4bvCRBvdSiNXdWGCZQmFVzBZZ/9rOLzP
pvTFTPnpkavJm81FLlUhiE/oFgKlCDLWDknSpXAI0uZGERcwPca6xvIMh86LjQKjbVci9FYDStXC
qRnqQ+TccSu/B6uONFsDEngGcXSKfB+a</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">phoebe.simon@scaleft.com</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="_213843b4-0693-47b8-b2f6-c41e316015cc" NotOnOrAfter="2016-03-22T19:27:57.054Z" Recipient="http://localhost:8080/v1/_saml_callback"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2016-03-22T19:17:57.054Z" NotOnOrAfter="2016-03-22T19:27:57.054Z" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:AudienceRestriction><saml2:Audience>123</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2016-03-22T19:22:57.054Z" SessionIndex="_213843b4-0693-47b8-b2f6-c41e316015cc" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:Attribute Name="FirstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Phoebe</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="LastName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Simon</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="Email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">phoebe.simon@scaleft.com</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion></saml2p:Response>`

const emptyReference = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_fd4fa4a5ab4b0c5e8bbc" Version="2.0" IssueInstant="2017-03-18T02:25:46Z" Destination="https://f1f51ddc.ngrok.io/api/sso/saml2/acs/58cafd0573d4f375b8e70e8e"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">a</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>1sl6AXnoU1CaZSx2MuDPLSKWAhGd6K40pcXe502u+Zw=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>jvr8AB4NzTi6FpZV27m6tsWtUXu4kPcCgx3vzE/T0om+DzOs0pkXhTD0H3oNqoWFOnpUo2dqO26nR58hzNpcIHPJPrHnNfboZJf68btzMNDa/OlnFtuwbFWo8Ac+rXS/Up3X5B3CNRlTz/W+ALZEuUHBGNZjE0Hw9Aav8YKAxiWx6uA9z0CCXUFVCbjmtrISMPSUQio+KjIc50j7BbVcezWTz/QB/ySsLEp/Zl4vCTCStFIkdZR/h3Ha5jovxsxuzERZ09x0l748dp8Cm449RnqOz4TIinxKz0xkqtFnbFmF1rFiGF8Vha2f7mdUqgmuy4ifevSI7G2ZQae3vQoNbw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDPDCCAiQCCQDydJgOlszqbzANBgkqhkiG9w0BAQUFADBgMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEQMA4GA1UEChMHSmFua3lDbzESMBAGA1UEAxMJbG9jYWxob3N0MB4XDTE0MDMxMjE5NDYzM1oXDTI3MTExOTE5NDYzM1owYDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xEDAOBgNVBAoTB0phbmt5Q28xEjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMGvJpRTTasRUSPqcbqCG+ZnTAurnu0vVpIG9lzExnh11o/BGmzu7lB+yLHcEdwrKBBmpepDBPCYxpVajvuEhZdKFx/Fdy6j5mH3rrW0Bh/zd36CoUNjbbhHyTjeM7FN2yF3u9lcyubuvOzr3B3gX66IwJlU46+wzcQVhSOlMk2tXR+fIKQExFrOuK9tbX3JIBUqItpI+HnAow509CnM134svw8PTFLkR6/CcMqnDfDK1m993PyoC1Y+N4X9XkhSmEQoAlAHPI5LHrvuujM13nvtoVYvKYoj7ScgumkpWNEvX652LfXOnKYlkB8ZybuxmFfIkzedQrbJsyOhfL03cMECAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAeHwzqwnzGEkxjzSD47imXaTqtYyETZow7XwBc0ZaFS50qRFJUgKTAmKS1xQBP/qHpStsROT35DUxJAE6NY1Kbq3ZbCuhGoSlY0L7VzVT5tpu4EY8+Dq/u2EjRmmhoL7UkskvIZ2n1DdERtd+YUMTeqYl9co43csZwDno/IKomeN5qaPc39IZjikJ+nUC6kPFKeu/3j9rgHNlRtocI6S1FdtFz9OZMQlpr0JbUt2T3xS/YoQJn6coDmJL5GTiiKM6cOe+Ur1VwzS1JEDbSS2TWWhzq8ojLdrotYLGd9JOsoQhElmz+tMfCFQUFLExinPAyy7YHlSiVX13QH2XTu/iQQ==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_f6vEQCp4nBCsBY3MeMleLgS6GfmIPAwy" IssueInstant="2017-03-18T02:25:46.951Z"><saml:Issuer>a</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">arun+okta@launchdarkly.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2017-03-18T03:25:46.951Z" Recipient="https://f1f51ddc.ngrok.io/api/sso/saml2/acs/58cafd0573d4f375b8e70e8e"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2017-03-18T02:25:46.951Z" NotOnOrAfter="2017-03-18T03:25:46.951Z"><saml:AudienceRestriction><saml:Audience>b</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><saml:Attribute Name="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"><saml:AttributeValue xsi:type="xs:anyType">arun+okta@launchdarkly.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="Email"><saml:AttributeValue xsi:type="xs:anyType">arun+okta@launchdarkly.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="FirstName"><saml:AttributeValue xsi:type="xs:anyType">Arun</saml:AttributeValue></saml:Attribute><saml:Attribute Name="LastName"><saml:AttributeValue xsi:type="xs:anyType">Bhalla</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AuthnStatement AuthnInstant="2017-03-18T02:25:46.951Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>`

const kycResp = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><REQ_ROOT><HEADER><REQUEST_ID>25337913</REQUEST_ID><FI_CODE>IN2780</FI_CODE><VERSION>1.1</VERSION></HEADER><CKYC_INQ><PID>ED+qNQIsf58u/0026jE3CtpPpf9AZ7FfvPaMxonMIMYgvPMTHuQejZnPmkKQaBqLWfxNC99XrwbJAy26AbTQIhNSHJsxBgDSYr4CFuSlm9t7WwRDU0GSxnFNGf6Rdix/bcz/59O6pbH9sumBaaPvdpH3/50nGlgUU5EfCyMKNwgyk40LfSQvQ7bpL3UysOktfW81VKB2ND98n5s4EhU3GIj/W7chKh5AYScVTbUgmLVf564pXdCSoA+5oVIdpNq9</PID><SESSION_KEY>mPkLG/KrEZ8BB7w+Pzt/vlZx1f5CxMu17MEKHLnP4NcXXQ7MJB6lp81x8rThVcEscuOyK2q03eBg0LkeYnYpnRwA25cEcz5MqzQODijlIuLSPNEtvcwU1Eus16IymbilnoWLbsPSfLfakEKm3CaXdoAcPfPWP+MUNcfoHXQEvhUPz5xxg1HwkAwkcvmreHGEsiZ68QbtzLA7+EhqftL4ya6UF0+5jcqWfLDdQZssNnuy7K2GH8IjYGXImDC7hecEUpMLSyrtdXDAa2FMRvvQvrBQLkAUCavLHtVjdbumcjBbH+5CLhtbpfE0HwQ1o6j9hxVGa1sAr2KOcSajdsDURw==</SESSION_KEY></CKYC_INQ><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI="#Mlnqc0C2syuXcwbMTSoKAslUP8KgrUqY"><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>vuED4akc0ZH5Y3kzbKKHXlXnH9I=</DigestValue></Reference></SignedInfo><SignatureValue>uadR54NM/z0sNVXB23mf+MjTJgw/gwLK05zYz34q7jNpRyEvtLHrvuUwAvHQKZcGW+ToQByuZpbkrqbEtiHJhNn9LlvsZRkLf4p0nZgRq7S3lZ5K+dHacYRKFTOdaaAwZ1g73R8T17Sv6q7r2zVS+0LQugMZCG5VuDEu2elpNr0IyyVvh4PgBVIGrmqZw7tnbqXTbxlcdl9HBaKLEATpXwiSC/6kKj1AL4f0n4p8zkLPS19cZvzCHHPYycYnOJpZ4P3ZwNTyPRQqsyU58wRsf3dR2YbgtGQT5X+X0NYMV44h8MDiuif/i/8y9vTU2RzEOx8V6SqaqjhkHYMcqEmoeA==</SignatureValue><KeyInfo><X509Data><X509Certificate>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</X509Certificate><X509SubjectName>SERIALNUMBER=c3ebda3e17911f30296765259e1009835fadaa558876daee40a396a98acec158,CN=DS Zerodha Capital Pvt. Ltd. 01,OU=Management,O=Zerodha Capital Pvt. Ltd.,POSTALCODE=560078,ST=Karnataka,C=IN</X509SubjectName></X509Data></KeyInfo></Signature></REQ_ROOT>`

const oktaCert = `
-----BEGIN CERTIFICATE-----
MIIDPDCCAiQCCQDydJgOlszqbzANBgkqhkiG9w0BAQUFADBgMQswCQYDVQQGEwJV
UzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEQ
MA4GA1UEChMHSmFua3lDbzESMBAGA1UEAxMJbG9jYWxob3N0MB4XDTE0MDMxMjE5
NDYzM1oXDTI3MTExOTE5NDYzM1owYDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNh
bGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xEDAOBgNVBAoTB0phbmt5
Q28xEjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMGvJpRTTasRUSPqcbqCG+ZnTAurnu0vVpIG9lzExnh11o/BGmzu7lB+
yLHcEdwrKBBmpepDBPCYxpVajvuEhZdKFx/Fdy6j5mH3rrW0Bh/zd36CoUNjbbhH
yTjeM7FN2yF3u9lcyubuvOzr3B3gX66IwJlU46+wzcQVhSOlMk2tXR+fIKQExFrO
uK9tbX3JIBUqItpI+HnAow509CnM134svw8PTFLkR6/CcMqnDfDK1m993PyoC1Y+
N4X9XkhSmEQoAlAHPI5LHrvuujM13nvtoVYvKYoj7ScgumkpWNEvX652LfXOnKYl
kB8ZybuxmFfIkzedQrbJsyOhfL03cMECAwEAATANBgkqhkiG9w0BAQUFAAOCAQEA
eHwzqwnzGEkxjzSD47imXaTqtYyETZow7XwBc0ZaFS50qRFJUgKTAmKS1xQBP/qH
pStsROT35DUxJAE6NY1Kbq3ZbCuhGoSlY0L7VzVT5tpu4EY8+Dq/u2EjRmmhoL7U
kskvIZ2n1DdERtd+YUMTeqYl9co43csZwDno/IKomeN5qaPc39IZjikJ+nUC6kPF
Keu/3j9rgHNlRtocI6S1FdtFz9OZMQlpr0JbUt2T3xS/YoQJn6coDmJL5GTiiKM6
cOe+Ur1VwzS1JEDbSS2TWWhzq8ojLdrotYLGd9JOsoQhElmz+tMfCFQUFLExinPA
yy7YHlSiVX13QH2XTu/iQQ==
-----END CERTIFICATE-----
`

func TestDigest(t *testing.T) {
	canonicalizer := MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	doc := etree.NewDocument()
	err := doc.ReadFromBytes([]byte(canonicalResponse))
	require.NoError(t, err)

	vc := NewDefaultValidationContext(nil)
	digest, err := vc.digest(doc.Root(), "http://www.w3.org/2001/04/xmlenc#sha256", canonicalizer)
	require.NoError(t, err)
	require.Equal(t, "gvXF2ygtu4WbVYdepEtHFbgCZLfKW893eFF+x6gjX80=", base64.StdEncoding.EncodeToString(digest))

	doc = etree.NewDocument()
	err = doc.ReadFromBytes([]byte(canonicalResponse2))
	require.NoError(t, err)

	vc = NewDefaultValidationContext(nil)
	digest, err = vc.digest(doc.Root(), "http://www.w3.org/2001/04/xmlenc#sha256", canonicalizer)
	require.NoError(t, err)
	require.Equal(t, "npTAl6kraksBlCRlunbyD6nICTcfsDaHjPXVxoDPrw0=", base64.StdEncoding.EncodeToString(digest))

}

func TestTransform(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromBytes([]byte(rawResponse))
	require.NoError(t, err)

	vc := NewDefaultValidationContext(nil)

	el := doc.Root()

	sig, err := vc.findSignature(el)
	require.NoError(t, err)

	ref := &sig.SignedInfo.References[0]

	transformed, canonicalizer, err := vc.transform(el, sig, ref)
	require.NoError(t, err)
	require.NotEmpty(t, transformed)
	require.IsType(t, &c14N10ExclusiveCanonicalizer{}, canonicalizer)

	doc = etree.NewDocument()
	doc.SetRoot(transformed)

	str, err := doc.WriteToString()
	require.NoError(t, err)
	require.Equal(t, expectedTransformation, str)
}
func TestValidateKYCSignatureRef(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromBytes([]byte(kycResp))
	require.NoError(t, err)

	vc := NewKYCValidationContext(nil)

	el := doc.Root()

	sig, err := vc.findSignature(el)
	require.NoError(t, err)

	ref := &sig.SignedInfo.References[0]

	transformed, canonicalizer, err := vc.transform(el, sig, ref)
	require.NoError(t, err)
	require.NotEmpty(t, transformed)
	require.IsType(t, &c14N10ExclusiveCanonicalizer{}, canonicalizer)

	doc = etree.NewDocument()
	doc.SetRoot(transformed)

	str, err := doc.WriteToString()
	require.NoError(t, err)
	require.Equal(t, expectedTransformation, str)
}
func TestValidateWithEmptySignatureReference(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromBytes([]byte(emptyReference))
	require.NoError(t, err)

	sig := doc.FindElement("//" + SignatureTag)
	require.NotEmpty(t, sig)

	// Verify that Reference URI is empty
	signedInfo := sig.FindElement(childPath(sig.Space, SignedInfoTag))
	require.NotEmpty(t, signedInfo)
	reference := signedInfo.FindElement(childPath(sig.Space, ReferenceTag))
	require.NotEmpty(t, reference)
	require.Empty(t, reference.SelectAttr(URIAttr).Value)

	block, _ := pem.Decode([]byte(oktaCert))
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "couldn't parse okta cert pem block")

	certStore := MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	}
	vc := NewDefaultValidationContext(&certStore)

	el, err := vc.Validate(doc.Root())
	require.NoError(t, err)
	require.NotEmpty(t, el)
}
