package dsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"

	// implimenting sha1 and sha256.
	_ "crypto/sha1"
	_ "crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// SigningContext is a base structure for signing.
type SigningContext struct {
	Hash          crypto.Hash
	KeyStore      X509KeyStore
	IDAttribute   string
	Prefix        string
	Canonicalizer Canonicalizer
}

// NewDefaultSigningContext is for creating a default signing context.
func NewDefaultSigningContext(ks X509KeyStore) *SigningContext {
	return &SigningContext{
		Hash:          crypto.SHA256,
		KeyStore:      ks,
		IDAttribute:   DefaultIDAttr,
		Prefix:        DefaultPrefix,
		Canonicalizer: MakeC14N11Canonicalizer(),
	}
}

// NewKYCSigningContext creates a new context for KYC signging
func NewKYCSigningContext(ks X509KeyStore) *SigningContext {
	return &SigningContext{
		Hash:          crypto.SHA1,
		KeyStore:      ks,
		IDAttribute:   KYCIDAttr,
		Prefix:        EmptyPrefix,
		Canonicalizer: MakeC14N10RecCanonicalizer(),
	}
}

// SetSignatureMethod to set signature method.
func (ctx *SigningContext) SetSignatureMethod(algorithmID string) error {
	hash, ok := signatureMethodsByIdentifier[algorithmID]
	if !ok {
		return fmt.Errorf("Unknown SignatureMethod: %s", algorithmID)
	}

	ctx.Hash = hash

	return nil
}

// digest will create digest of the signature.
func (ctx *SigningContext) digest(el *etree.Element) ([]byte, error) {
	canonical, err := ctx.Canonicalizer.Canonicalize(el)
	if err != nil {
		return nil, err
	}

	hash := ctx.Hash.New()
	_, err = hash.Write(canonical)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

// constructSignedInfo will create etree nodes for signed info tag.
func (ctx *SigningContext) constructSignedInfo(el *etree.Element, enveloped bool) (*etree.Element, error) {
	digestAlgorithmIdentifier := ctx.GetDigestAlgorithmIdentifier()
	if digestAlgorithmIdentifier == "" {
		return nil, errors.New("unsupported hash mechanism")
	}

	signatureMethodIdentifier := ctx.GetSignatureMethodIdentifier()
	if signatureMethodIdentifier == "" {
		return nil, errors.New("unsupported signature method")
	}

	digest, err := ctx.digest(el)
	if err != nil {
		return nil, err
	}

	signedInfo := &etree.Element{
		Tag:   SignedInfoTag,
		Space: ctx.Prefix,
	}

	// /SignedInfo/CanonicalizationMethod
	canonicalizationMethod := ctx.createNamespacedElement(signedInfo, CanonicalizationMethodTag)
	canonicalizationMethod.CreateAttr(AlgorithmAttr, string(ctx.Canonicalizer.Algorithm()))

	// /SignedInfo/SignatureMethod
	signatureMethod := ctx.createNamespacedElement(signedInfo, SignatureMethodTag)
	signatureMethod.CreateAttr(AlgorithmAttr, signatureMethodIdentifier)

	// /SignedInfo/Reference
	reference := ctx.createNamespacedElement(signedInfo, ReferenceTag)

	dataID := el.SelectAttrValue(ctx.IDAttribute, "")
	if dataID == "" {
		return nil, errors.New("Missing data ID")
	}

	reference.CreateAttr(URIAttr, "#"+dataID)

	// // /SignedInfo/Reference/Transforms
	transforms := ctx.createNamespacedElement(reference, TransformsTag)
	if enveloped {
		envelopedTransform := ctx.createNamespacedElement(transforms, TransformTag)
		envelopedTransform.CreateAttr(AlgorithmAttr, EnvelopedSignatureAltorithmID.String())
	}
	canonicalizationAlgorithm := ctx.createNamespacedElement(transforms, TransformTag)
	canonicalizationAlgorithm.CreateAttr(AlgorithmAttr, string(ctx.Canonicalizer.Algorithm()))

	// /SignedInfo/Reference/DigestMethod
	digestMethod := ctx.createNamespacedElement(reference, DigestMethodTag)
	digestMethod.CreateAttr(AlgorithmAttr, digestAlgorithmIdentifier)

	// /SignedInfo/Reference/DigestValue
	digestValue := ctx.createNamespacedElement(reference, DigestValueTag)
	digestValue.SetText(base64.StdEncoding.EncodeToString(digest))

	return signedInfo, nil
}

// ConstructSignature will construct etree nodes for signature.
func (ctx *SigningContext) ConstructSignature(el *etree.Element, enveloped bool) (*etree.Element, error) {
	signedInfo, err := ctx.constructSignedInfo(el, enveloped)
	if err != nil {
		return nil, err
	}

	sig := &etree.Element{
		Tag:   SignatureTag,
		Space: ctx.Prefix,
	}

	xmlns := "xmlns"
	if ctx.Prefix != "" {
		xmlns += ":" + ctx.Prefix
	}

	sig.CreateAttr(xmlns, Namespace)
	sig.AddChild(signedInfo)

	// When using xml-c14n11 (ie, non-exclusive canonicalization) the canonical form
	// of the SignedInfo must declare all namespaces that are in scope at it's final
	// enveloped location in the document. In order to do that, we're going to construct
	// a series of cascading NSContexts to capture namespace declarations:

	// First get the context surrounding the element we are signing.
	rootNSCtx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, err
	}

	// Then capture any declarations on the element itself.
	elNSCtx, err := rootNSCtx.SubContext(el)
	if err != nil {
		return nil, err
	}

	// Followed by declarations on the Signature (which we just added above)
	sigNSCtx, err := elNSCtx.SubContext(sig)
	if err != nil {
		return nil, err
	}

	// Finally detatch the SignedInfo in order to capture all of the namespace
	// declarations in the scope we've constructed.
	detatchedSignedInfo, err := etreeutils.NSDetatch(sigNSCtx, signedInfo)
	if err != nil {
		return nil, err
	}
	detatchedSignedInfo.RemoveAttr("xmlns:xsi")

	digest, err := ctx.digest(detatchedSignedInfo)
	if err != nil {
		return nil, err
	}

	key, cert, err := ctx.KeyStore.GetKeyPair()
	if err != nil {
		return nil, err
	}

	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, key, ctx.Hash, digest)
	if err != nil {
		return nil, err
	}

	signatureValue := ctx.createNamespacedElement(sig, SignatureValueTag)
	signatureValue.SetText(base64.StdEncoding.EncodeToString(rawSignature))

	keyInfo := ctx.createNamespacedElement(sig, KeyInfoTag)
	x509Data := ctx.createNamespacedElement(keyInfo, X509DataTag)

	x509Certificate := ctx.createNamespacedElement(x509Data, X509CertificateTag)
	sub := cert.Subject.String()
	if sub != "" {
		x509Subject := ctx.createNamespacedElement(x509Data, X509SubjectNameTag)
		x509Subject.SetText(sub)
	}
	x509Certificate.SetText(base64.StdEncoding.EncodeToString(cert.Raw))

	return sig, nil
}

func (ctx *SigningContext) createNamespacedElement(el *etree.Element, tag string) *etree.Element {
	child := el.CreateElement(tag)
	child.Space = ctx.Prefix
	return child
}

// SignEnveloped creates etree element for envelope.
func (ctx *SigningContext) SignEnveloped(el *etree.Element) (*etree.Element, error) {
	sig, err := ctx.ConstructSignature(el, true)
	if err != nil {
		return nil, err
	}

	ret := el.Copy()
	ret.Child = append(ret.Child, sig)

	return ret, nil
}

// GetSignatureMethodIdentifier returns identifier string.
func (ctx *SigningContext) GetSignatureMethodIdentifier() string {
	if ident, ok := signatureMethodIdentifiers[ctx.Hash]; ok {
		return ident
	}
	return ""
}

// GetDigestAlgorithmIdentifier returns digest identifier.
func (ctx *SigningContext) GetDigestAlgorithmIdentifier() string {
	if ident, ok := digestAlgorithmIdentifiers[ctx.Hash]; ok {
		return ident
	}
	return ""
}

// SignString is useful for signing query string (including DEFLATED AuthnRequest) when
// using HTTP-Redirect to make a signed request.
// See 3.4.4.1 DEFLATE Encoding of https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
func (ctx *SigningContext) SignString(content string) ([]byte, error) {
	hash := ctx.Hash.New()
	if ln, err := hash.Write([]byte(content)); err != nil {
		return nil, fmt.Errorf("error calculating hash: %v", err)
	} else if ln < 1 {
		return nil, fmt.Errorf("zero length hash")
	}
	digest := hash.Sum(nil)

	var signature []byte
	if key, _, err := ctx.KeyStore.GetKeyPair(); err != nil {
		return nil, fmt.Errorf("unable to fetch key for signing: %v", err)
	} else if signature, err = rsa.SignPKCS1v15(rand.Reader, key, ctx.Hash, digest); err != nil {
		return nil, fmt.Errorf("error signing: %v", err)
	}
	return signature, nil
}
