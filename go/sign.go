package signedhttpmessages

import (
	"encoding/base64"
	"net/http"
)

func Sign(key []byte, req *http.Request, sp *SigParams) error {
	sp.Signature = "placeholder"
	if err := sp.validate(req); err != nil {
		return err
	}
	sigInput, err := sp.generateSigInput(req)
	if err != nil {
		return err
	}
	sig, err := sp.Algorithm.sign(key, sigInput)
	if err != nil {
		return err
	}
	sp.Signature = base64.StdEncoding.EncodeToString(sig)

	req.Header.Add("Signature", sp.toSignatureHeaderValue())

	return nil
}
