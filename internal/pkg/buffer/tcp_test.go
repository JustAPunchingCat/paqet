package buffer
import ("context"; "io"; "net"; "testing"; "bytes")
func TestRelayTCP(t *testing.T) {
	client, server := net.Pipe()
	remoteClient, remoteServer := net.Pipe()
	payload := []byte("hello world")
	go func() {
		remoteServer.Write(payload)
		remoteServer.Close()
	}()
	go func() {
		RelayTCP(context.Background(), remoteClient, server)
	}()
	buf := new(bytes.Buffer)
	io.Copy(buf, client)
	if !bytes.Equal(buf.Bytes(), payload) { t.Fatalf("failed") }
}