package canonical

import jsoncanonicalizer "webpki.org/jsoncanonicalizer"

func JSON(body []byte) ([]byte, error) {
  return jsoncanonicalizer.Transform(body)
}
