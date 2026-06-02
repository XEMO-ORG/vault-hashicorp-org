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
)

var stepCount = 0

// From builtin/credential/cert/test-fixtures/root/rootcacert.pem
const (
	rootCACertPEM = `-----BEGIN CERTIFICATE-----
MIIDPDCCAiSgAwIBAgIUb5id+GcaMeMnYBv3MvdTGWigyJ0wDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAxMLZXhhbXBsZS5jb20wHhcNMTYwMjI5MDIyNzI5WhcNMjYw
MjI2MDIyNzU5WjAWMRQwEgYDVQQDEwtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAOxTMvhTuIRc2YhxZpmPwegP86cgnqfT1mXxi1A7
Q7qax24Nqbf00I3oDMQtAJlj2RB3hvRSCb0/lkF7i1Bub+TGxuM7NtZqp2F8FgG0
z2md+W6adwW26rlxbQKjmRvMn66G9YPTkoJmPmxt2Tccb9+apmwW7lslL5j8H48x
AHJTMb+PMP9kbOHV5Abr3PT4jXUPUr/mWBvBiKiHG0Xd/HEmlyOEPeAThxK+I5tb
6m+eB+7cL9BsvQpy135+2bRAxUphvFi5NhryJ2vlAvoJ8UqigsNK3E28ut60FAoH
SWRfFUFFYtfPgTDS1yOKU/z/XMU2giQv2HrleWt0mp4jqBUCAwEAAaOBgTB/MA4G
A1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSdxLNP/ocx
7HK6JT3/sSAe76iTmzAfBgNVHSMEGDAWgBSdxLNP/ocx7HK6JT3/sSAe76iTmzAc
BgNVHREEFTATggtleGFtcGxlLmNvbYcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEA
wHThDRs