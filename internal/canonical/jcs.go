package canonical

import jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"

func JSON(body []byte) ([]byte, error) {
	return jsoncanonicalizer.Transform(body)
}
