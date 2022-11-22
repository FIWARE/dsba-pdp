package migrations

import "github.com/go-rel/rel"

func MigrateCreateTrustedIssuers(schema *rel.Schema) {
	schema.CreateTable("trusted_issuers", func(t *rel.Table) {
		t.String("id")
		t.PrimaryKey("id")
	})
}

func RollbackCreateTrustedIssuers(schema *rel.Schema) {
	schema.DropTable("trusted_issuers")
}
