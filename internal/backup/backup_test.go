package backup

import (
	"bytes"
	"strings"
	"testing"
)

var backupKey = []byte("a-test-secret-key-that-is-long-enough")

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plain := []byte("SQLite format 3\x00 and then some database bytes")

	enc, err := encrypt(plain, backupKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(enc, plain) {
		t.Error("encrypted backup contains the plaintext")
	}

	got, err := Decrypt(enc, backupKey)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("round trip did not return the original bytes")
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	enc, _ := encrypt([]byte("database"), backupKey)
	if _, err := Decrypt(enc, []byte("a-completely-different-key-value-x")); err == nil {
		t.Error("backup decrypted with the wrong key")
	}
}

func TestDecryptRejectsCorruptBackup(t *testing.T) {
	enc, _ := encrypt([]byte("database"), backupKey)

	tampered := make([]byte, len(enc))
	copy(tampered, enc)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := Decrypt(tampered, backupKey); err == nil {
		t.Error("tampered backup was accepted")
	}

	for _, bad := range [][]byte{{}, []byte("short"), bytes.Repeat([]byte{0}, 12)} {
		if _, err := Decrypt(bad, backupKey); err == nil {
			t.Errorf("truncated backup of %d bytes was accepted", len(bad))
		}
	}
}

func TestEncryptionIsNonDeterministic(t *testing.T) {
	a, _ := encrypt([]byte("same"), backupKey)
	b, _ := encrypt([]byte("same"), backupKey)
	if bytes.Equal(a, b) {
		t.Error("two encryptions of the same data produced identical output")
	}
}

func TestScheduleInterval(t *testing.T) {
	cases := map[string]bool{
		"manual": false,
		"":       false,
		"hourly": true,
		"daily":  true,
		"weekly": true,
	}
	for schedule, wantRuns := range cases {
		got := ScheduleInterval(schedule)
		if wantRuns && got <= 0 {
			t.Errorf("ScheduleInterval(%q) = %v, want a positive interval", schedule, got)
		}
		if !wantRuns && got > 0 {
			t.Errorf("ScheduleInterval(%q) = %v, want no scheduled runs", schedule, got)
		}
	}
	if ScheduleInterval("hourly") >= ScheduleInterval("daily") {
		t.Error("hourly should run more often than daily")
	}
	if ScheduleInterval("daily") >= ScheduleInterval("weekly") {
		t.Error("daily should run more often than weekly")
	}
}

func TestSQLiteHeaderSurvivesRoundTrip(t *testing.T) {
	plain := append([]byte("SQLite format 3\x00"), bytes.Repeat([]byte{0x42}, 512)...)
	enc, _ := encrypt(plain, backupKey)
	got, err := Decrypt(enc, backupKey)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !strings.HasPrefix(string(got), "SQLite format 3\x00") {
		t.Error("SQLite header missing after decryption")
	}
}
