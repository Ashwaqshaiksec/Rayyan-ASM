package toolrunner

import (
	"encoding/json"

	cryptoutil "github.com/ShadooowX/rayyan-asm/internal/crypto"
	"github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// toolCredentialRow mirrors models.ToolCredential for querying without
// importing the models package (avoids an import cycle: models is imported
// by handlers, which imports toolrunner).
type toolCredentialRow struct {
	EncryptedSecret string `gorm:"column:encrypted_secret"`
}

func (toolCredentialRow) TableName() string { return "tool_credentials" }

// LoadCredentials fetches and decrypts the most recently created stored
// credential for the given org + tool. Returns nil, nil if no
// credential is configured or credential storage is disabled (key not
// 32 bytes).
func LoadCredentials(db *gorm.DB, key []byte, orgID uuid.UUID, toolName string) (*types.ToolCredentials, error) {
	if len(key) != 32 {
		return nil, nil
	}

	var row toolCredentialRow
	err := db.Where("org_id = ? AND tool_name = ?", orgID, toolName).
		Order("created_at desc").
		First(&row).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}

	plaintext, err := cryptoutil.Decrypt(key, row.EncryptedSecret)
	if err != nil {
		return nil, err
	}

	var tc types.ToolCredentials
	if err := json.Unmarshal(plaintext, &tc); err != nil {
		return nil, err
	}
	return &tc, nil
}
