package migrations

import "github.com/go-rel/rel"

func MigrateCreateCapabilities(schema *rel.Schema) {
	schema.CreateTable("capabilities", func(t *rel.Table) {
		t.ID("id")
		t.String("valid_from")
		t.String("valid_to")
		t.String("credentials_type")
		t.String("trusted_issuer")
		t.ForeignKey("trusted_issuer", "trusted_issuers", "id")
	})

}

func RollbackCreateCapabilities(schema *rel.Schema) {
	schema.DropTable("capabilities")
}
