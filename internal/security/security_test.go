package security

import (
	"bytes"
	"testing"
	"time"
)

func TestPairingBindsSigningAndNoiseKeys(t *testing.T) {
	mate, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	device, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	manager := NewPairingManager("mate-1", "wss://relay.example", mate)
	bundle, err := manager.Issue(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	presentation, err := SignPresentation(bundle.OneTimeToken, bundle.MateID, device, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	record, err := manager.Complete(bundle.OneTimeToken, presentation)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDeviceRecord(record, mate.SigningPublic) {
		t.Fatal("mate binding did not verify")
	}
	if _, err := manager.Complete(bundle.OneTimeToken, presentation); err == nil {
		t.Fatal("one-time token was accepted twice")
	}
}

func TestInvalidPresentationDoesNotBurnPairingToken(t *testing.T) {
	mate, _ := GenerateIdentity()
	device, _ := GenerateIdentity()
	manager := NewPairingManager("mate-1", "wss://relay.example", mate)
	bundle, err := manager.Issue(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	presentation, _ := SignPresentation(bundle.OneTimeToken, bundle.MateID, device, "device-1")
	presentation.Signature[0] ^= 0xff
	if _, err := manager.Complete(bundle.OneTimeToken, presentation); err == nil {
		t.Fatal("invalid presentation was accepted")
	}
	presentation, _ = SignPresentation(bundle.OneTimeToken, bundle.MateID, device, "device-1")
	if _, err := manager.Complete(bundle.OneTimeToken, presentation); err != nil {
		t.Fatalf("valid presentation failed after invalid attempt: %v", err)
	}
}

func TestPairingValidationAndQRPayload(t *testing.T) {
	mate, _ := GenerateIdentity()
	device, _ := GenerateIdentity()
	manager := NewPairingManager("mate", "relay", mate)
	if _, err := manager.Issue(0); err == nil {
		t.Fatal("non-positive TTL accepted")
	}
	if _, err := manager.Complete("invalid", DevicePresentation{}); err == nil {
		t.Fatal("invalid token accepted")
	}
	bundle, _ := manager.Issue(time.Minute)
	if payload, err := bundle.QRPayload(); err != nil || payload == "" {
		t.Fatalf("QR payload=%q err=%v", payload, err)
	}
	presentation, _ := SignPresentation(bundle.OneTimeToken, bundle.MateID, device, "")
	if _, err := manager.Complete(bundle.OneTimeToken, presentation); err == nil {
		t.Fatal("empty device ID accepted")
	}
}

func TestExpiredPairingToken(t *testing.T) {
	mate, _ := GenerateIdentity()
	device, _ := GenerateIdentity()
	now := time.Now()
	manager := NewPairingManager("mate", "relay", mate)
	manager.now = func() time.Time { return now }
	bundle, err := manager.Issue(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	presentation, _ := SignPresentation(bundle.OneTimeToken, bundle.MateID, device, "device")
	now = now.Add(2 * time.Second)
	if _, err := manager.Complete(bundle.OneTimeToken, presentation); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestIdentityHelpersAndRecordValidation(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if PublicKeyString(identity.SigningPublic) == "" || IdentityID(identity)[:5] != "axon-" {
		t.Fatal("identity helpers returned empty values")
	}
	if VerifyDeviceRecord(DeviceRecord{}, identity.SigningPublic) {
		t.Fatal("empty record verified")
	}
}

func TestNoiseIKChannelsInteroperate(t *testing.T) {
	mate, _ := GenerateIdentity()
	device, _ := GenerateIdentity()
	prologue := []byte("mesh-axon-v1:mate-1:device-1")
	initiator, err := NewIKInitiator(device.Noise, mate.Noise.Public, prologue)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewIKResponder(mate.Noise, prologue)
	if err != nil {
		t.Fatal(err)
	}
	first, err := initiator.Start([]byte("device-1"))
	if err != nil {
		t.Fatal(err)
	}
	gotIdentity, err := responder.Accept(first, device.Noise.Public)
	if err != nil || !bytes.Equal(gotIdentity, []byte("device-1")) {
		t.Fatalf("responder payload: %q, %v", gotIdentity, err)
	}
	second, responderChannel, err := responder.Reply([]byte("mate-1"))
	if err != nil {
		t.Fatal(err)
	}
	gotMate, initiatorChannel, err := initiator.Finish(second)
	if err != nil || !bytes.Equal(gotMate, []byte("mate-1")) {
		t.Fatalf("initiator payload: %q, %v", gotMate, err)
	}
	ciphertext, err := initiatorChannel.Send.Encrypt(nil, nil, []byte("secret terminal output"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := responderChannel.Recv.Decrypt(nil, nil, ciphertext)
	if err != nil || !bytes.Equal(plaintext, []byte("secret terminal output")) {
		t.Fatalf("decrypted: %q, %v", plaintext, err)
	}
}

func TestNoiseIKRejectsUnpairedInitiator(t *testing.T) {
	mate, _ := GenerateIdentity()
	paired, _ := GenerateIdentity()
	attacker, _ := GenerateIdentity()
	initiator, _ := NewIKInitiator(attacker.Noise, mate.Noise.Public, nil)
	responder, _ := NewIKResponder(mate.Noise, nil)
	first, _ := initiator.Start(nil)
	if _, err := responder.Accept(first, paired.Noise.Public); err == nil {
		t.Fatal("unpaired initiator was accepted")
	}
}

func TestNoiseRejectsInvalidStateTransitions(t *testing.T) {
	mate, _ := GenerateIdentity()
	device, _ := GenerateIdentity()
	initiator, _ := NewIKInitiator(device.Noise, mate.Noise.Public, nil)
	if _, err := initiator.Start(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := initiator.Start(nil); err == nil {
		t.Fatal("initiator wrote two first messages")
	}
	initiator, _ = NewIKInitiator(device.Noise, mate.Noise.Public, nil)
	if _, _, err := initiator.Finish([]byte("invalid")); err == nil {
		t.Fatal("initiator accepted invalid reply")
	}
	responder, _ := NewIKResponder(mate.Noise, nil)
	if _, err := responder.Accept([]byte("invalid"), device.Noise.Public); err == nil {
		t.Fatal("responder accepted invalid message")
	}
	responder, _ = NewIKResponder(mate.Noise, nil)
	if _, _, err := responder.Reply(nil); err == nil {
		t.Fatal("responder replied before accepting initiator")
	}
	invalid := mate.Noise
	invalid.Private = nil
	if _, err := NewIKInitiator(invalid, device.Noise.Public, nil); err == nil {
		t.Fatal("invalid initiator key accepted")
	}
	if _, err := NewIKResponder(invalid, nil); err == nil {
		t.Fatal("invalid responder key accepted")
	}
}
