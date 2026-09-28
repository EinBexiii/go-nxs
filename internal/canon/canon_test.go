package canon

import "testing"

func TestArray(t *testing.T) {
	got, err := Array("nethernet-external-signaling-v1", "a\"b\\c\n\x01<é🦊>", int64(1788484200123), 2, uint64(17))
	if err != nil {
		t.Fatal(err)
	}
	const want = `["nethernet-external-signaling-v1","a\"b\\c\n\u0001<é🦊>",1788484200123,2,17]`
	if string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if _, err := Array("\xff"); err == nil {
		t.Fatal("expected error for invalid UTF-8")
	}
}
