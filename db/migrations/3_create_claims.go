package migrations

import "github.com/go-rel/rel"

func MigrateCreateClaims(schema *rel.Schema) {
	schema.CreateTable("claims", func(t *rel.Table) {
		t.ID("id")
		t.String("name")
		t.Int("capability", rel.Scale(10), rel.Unsigned(true))
		t.ForeignKey("capability", "capabilities", "id")
	})
}

func RollbackCreateClaims(schema *rel.Schema) {
	schema.DropTable("claims")
}
