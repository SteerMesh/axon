package main

import (
	"encoding/base64"
	"encoding/json"
	"os"

	"github.com/SteerMesh/axon/internal/security"
)

type message struct {
	MatePublic   string `json:"mate_public,omitempty"`
	DevicePublic string `json:"device_public,omitempty"`
	Prologue     string `json:"prologue,omitempty"`
	Payload      string `json:"payload,omitempty"`
}

func main() {
	decoder, encoder := json.NewDecoder(os.Stdin), json.NewEncoder(os.Stdout)
	mate, err := security.GenerateIdentity()
	must(err)
	must(encoder.Encode(message{MatePublic: encode(mate.Noise.Public)}))

	var request message
	must(decoder.Decode(&request))
	devicePublic := decode(request.DevicePublic)
	responder, err := security.NewIKResponder(mate.Noise, decode(request.Prologue))
	must(err)
	_, err = responder.Accept(decode(request.Payload), devicePublic)
	must(err)
	reply, channel, err := responder.Reply([]byte("mate-accepted"))
	must(err)
	must(encoder.Encode(message{Payload: encode(reply)}))

	must(decoder.Decode(&request))
	plaintext, err := channel.Recv.Decrypt(nil, nil, decode(request.Payload))
	must(err)
	ciphertext, err := channel.Send.Encrypt(nil, nil, append([]byte("echo:"), plaintext...))
	must(err)
	must(encoder.Encode(message{Payload: encode(ciphertext)}))
}

func encode(value []byte) string { return base64.RawStdEncoding.EncodeToString(value) }

func decode(value string) []byte {
	decoded, err := base64.RawStdEncoding.DecodeString(value)
	must(err)
	return decoded
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
