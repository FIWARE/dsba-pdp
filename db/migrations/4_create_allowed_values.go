package migrations

import "github.com/go-rel/rel"

func MigrateCreateAllowedValues(schema *rel.Schema) {
	schema.CreateTable("allowed_values", func(t *rel.Table) {
		t.ID("id")
		t.String("allowed_string")
		t.Int("allowed_number")
		t.Bool("allowed_boolean")
		t.JSON("allowed_rolevalue")
		t.Int("claim", rel.Scale(10), rel.Unsigned(true))
		t.ForeignKey("claim", "claims", "id")
	})
}

func RollbackCreateAllowedValues(schema *rel.Schema) {
	schema.DropTable("allowed_values")
}
