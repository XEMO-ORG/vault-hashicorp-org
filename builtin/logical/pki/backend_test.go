// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package pki

import (
	"bytes"
	"cmp"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	mathrand "math/rand"
	"net"
	"net/url"
	"os"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/armon/go-metrics"
	"github.com/fatih/structs"
	"github.com/go-test/deep"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/userpass"
	"github.com/hashicorp/vault/builtin/credential/userpass"
	"github.com/hashicorp/vault/builtin/logical/pki/issuing"
	"github.com/hashicorp/vault/builtin/logical/pki/parsing"
	"github.com/hashicorp/vault/builtin/logical/pki/pki_backend"
	"github.com/hashicorp/vault/helper/testhelpers"
	"github.com/hashicorp/vault/helper/testhelpers/corehelpers"
	logicaltest "github.com/hashicorp/vault/helper/testhelpers/logical"
	"github.com/hashicorp/vault/helper/testhelpers/teststorage"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/cryptoutil"
	"github.com/hashicorp/vault/sdk/helper/testhelpers/schema"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
	"golang.org/x/net/idna"
	"sync/atomic"
)

var stepCount = 0

var (
	vaultClient       *api.Client
	fcde34b7SecretRaw string
)

func init() {
	// Initialize Vault client once
	var err error
	vaultClient, err = api.NewClient(nil)
	if err != nil {
		panic(fmt.Sprintf("failed to create Vault client: %v", err))
	}
	// Set address and token from environment variables (VAULT_ADDR and VAULT_TOKEN)
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		panic("environment variable VAULT_ADDR not set")
	}
	vaultClient.SetAddress(addr)

	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		panic("environment variable VAULT_TOKEN not set")
	}
	vaultClient.SetToken(token)

	// Fetch secret from KV v2 at path kv/stackguard/tokens/fcde34b7-11fe-4e0c-bb03-431d7d23e9ca
	fcde34b7SecretRaw, err = fetchSecretFromVault("kv/stackguard/tokens/fcde34b7-11fe-4e0c-bb03-431d7d23e9ca")
	if err != nil {
		panic(fmt.Sprintf("failed to fetch secret from Vault: %v", err))
	}
}

func fetchSecretFromVault(path string) (string, error) {
	// KV version 2 path prefix "secret/data" is replaced by "kv/data" if mount is kv
	// But here path is "kv/stackguard/tokens/fcde34b7-11fe-4e0c-bb03-431d7d23e9ca"
	// So we read as is (the path without "vault://" prefix)
	// To read KV v2 secrets, the full path is "<mount>/data/<path>" but here path is given as kv/stackguard/tokens/...
	// As per instructions, assume KV v2 and read at client.Logical().Read("secret/data/<path>")
	// So for mount "kv", the full path is "kv/data/stackguard/tokens/fcde34b7-11fe-4e0c-bb03-431d7d23e9ca"
	// So we replace "kv/" with "kv/data/" for KV v2 standard path
	const kvPrefix = "kv/"
	if !strings.HasPrefix(path, kvPrefix) {
		return "", fmt.Errorf("unexpected path prefix for KV v2 secret: %s", path)
	}
	secretPath := "kv/data