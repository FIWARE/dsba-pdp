package migrations

import "github.com/go-rel/rel"

func MigrateCreateAllowedValues(schema *rel.Schema) {
	schema.AlterTable("allowed_values", func(t *rel.AlterTable) {
		t.RenameColumn("allowed_value", "allowed_string")
		t.Int("allowed_number")
		t.Bool("allowed_boolean")
		t.JSON("allowed_rolevalue")
	})
}

func RollbackCreateAllowedValues(schema *rel.Schema) {
	schema.AlterTable("allowed_values", func(t *rel.AlterTable) {
		t.DropColumn("allowed_rolevalue")
		t.DropColumn("allowed_boolean")
		t.DropColumn("allowed_number")
		t.RenameColumn("allowed_string", "allowed_value")
	})
}
