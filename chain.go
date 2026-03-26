package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

type CertNode struct {
	PEMData string
	Subject string
	Issuer  string
	IsRoot  bool // true when Subject == Issuer
}

func ParseCertsFromFile(path string) ([]CertNode, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var nodes []CertNode
	rest := data
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}

		rest = remaining

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate block: %w", err)
		}

		subject := cert.Subject.String()
		issuer := cert.Issuer.String()

		nodes = append(nodes, CertNode{
			PEMData: string(pem.EncodeToMemory(block)),
			Subject: subject,
			Issuer:  issuer,
			IsRoot:  subject == issuer,
		})
	}

	if len(nodes) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE PEM blocks found — is this a valid certificate file")
	}
	return nodes, nil
}

func SortChain(certs []CertNode) ([]CertNode, error) {
	if len(certs) == 1 {
		return certs, nil
	}

	bySubject := make(map[string]CertNode, len(certs))
	for _, c := range certs {
		bySubject[c.Subject] = c
	}

	isIssuer := make(map[string]bool, len(certs))
	for _, c := range certs {
		isIssuer[c.Issuer] = true
	}

	var leaves []CertNode
	for _, c := range certs {
		if !isIssuer[c.Subject] {
			leaves = append(leaves, c)
		}
	}

	switch len(leaves) {
	case 0:
		return nil, fmt.Errorf("cannot determine leaf certificate, possible cycle in chain")
	case 1:
		// expected
	default:
		return nil, fmt.Errorf("found %d possible leaf certificates, expected exactly 1", len(leaves))
	}

	var sorted []CertNode
	visited := make(map[string]bool)
	current := leaves[0]

	for {
		if visited[current.Subject] {
			return nil, fmt.Errorf("cycle detected at: %s", CommonName(current.Subject))
		}
		visited[current.Subject] = true
		sorted = append(sorted, current)

		if current.IsRoot {
			break
		}

		next, ok := bySubject[current.Issuer]
		if !ok {
			// Issuer is not in the file, meaning the chain is incomplete. Stop here.
			break
		}

		current = next
	}

	return sorted, nil
}

func IsChainComplete(sorted []CertNode) bool {
	return len(sorted) > 0 && sorted[len(sorted)-1].IsRoot
}

func WriteChain(path string, sorted []CertNode, rootFirst bool) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if rootFirst {
		for i := len(sorted) - 1; i >= 0; i-- {
			if _, err := f.WriteString(sorted[i].PEMData); err != nil {
				return err
			}
		}
	} else {
		for _, c := range sorted {
			if _, err := f.WriteString(c.PEMData); err != nil {
				return err
			}
		}
	}

	return nil
}

// CommonName extracts a human-readable name from a full DN string.
// Prefers CN=, falls back to O=, then returns the raw string.
func CommonName(dn string) string {
	for _, prefix := range []string{"CN=", "O="} {
		for _, part := range strings.Split(dn, ",") {
			if trimmed := strings.TrimSpace(part); strings.HasPrefix(trimmed, prefix) {
				return strings.TrimPrefix(trimmed, prefix)
			}
		}
	}
	return dn
}
