package pgsql

import (
	"context"
	"os"
	"testing"

	_ "github.com/lib/pq"
	"github.com/micromdm/nanomdm/mdm"
)

func TestStoreCommandReportForDeletedCommand(t *testing.T) {
	testDSN := os.Getenv("NANOMDM_PGSQL_STORAGE_TEST_DSN")
	if testDSN == "" {
		t.Skip("NANOMDM_PGSQL_STORAGE_TEST_DSN not set")
	}
	s, err := New(WithDSN(testDSN))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const id = "DELETED-CMD-REPORT-DEVICE"
	_, err = s.db.ExecContext(ctx, `
INSERT INTO devices (id, authenticate, authenticate_at) VALUES ($1, 'authenticate', CURRENT_TIMESTAMP)
ON CONFLICT DO NOTHING;`, id)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO enrollments (id, device_id, type, topic, push_magic, token_hex, last_seen_at)
VALUES ($1, $1, 'Device', 'topic', 'magic', 'token', CURRENT_TIMESTAMP)
ON CONFLICT DO NOTHING;`, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.db.ExecContext(ctx, `DELETE FROM devices WHERE id = $1;`, id) })

	for _, cmdUUID := range []string{"DELETED-CMD", "NEXT-CMD"} {
		cmd := &mdm.Command{CommandUUID: cmdUUID, Raw: []byte("<?xml")}
		cmd.Command.RequestType = "DeviceInformation"
		if _, err = s.EnqueueCommand(ctx, []string{id}, cmd, false); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = s.db.ExecContext(ctx, `DELETE FROM commands WHERE command_uuid = 'NEXT-CMD';`) })
	if _, err = s.db.ExecContext(ctx, `DELETE FROM commands WHERE command_uuid = 'DELETED-CMD';`); err != nil {
		t.Fatal(err)
	}

	r := mdm.NewRequestWithContext(ctx, nil)
	r.EnrollID = &mdm.EnrollID{Type: mdm.Device, ID: id}
	report := &mdm.CommandResults{CommandUUID: "DELETED-CMD", Status: "Acknowledged", Raw: []byte("<?xml")}
	if err = s.StoreCommandReport(r, report); err != nil {
		t.Fatalf("want a report for a deleted command ignored, got %v", err)
	}
	next, err := s.RetrieveNextCommand(r, false)
	if err != nil {
		t.Fatal(err)
	}
	if next == nil || next.CommandUUID != "NEXT-CMD" {
		t.Errorf("want the next command NEXT-CMD, got %v", next)
	}
}
