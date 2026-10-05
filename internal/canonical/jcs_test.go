package canonical

import "testing"

func TestJSONCanonicalizesObjectKeyOrder(t *testing.T) {
  got, err := JSON([]byte("{"b":2,"a":1}"))
  if err != nil { t.Fatal(err) }
  if string(got) != "{"a":1,"b":2}" { t.Fatalf("got %s", got) }
}
