package crl

import (
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
    "math/big"

    "github.com/smallstep/cli-utils/errs"
    "github.com/smallstep/cli-utils/fileutil"
    "github.com/smallstep/cli-utils/ui"
    "github.com/smallstep/cli/internal/cryptoutil"
    "github.com/urfave/cli"
    "go.step.sm/crypto/pemutil"

    "github.com/smallstep/cli-utils/command"
)

func createCommand() cli.Command {
	return cli.Command{
		Name:      "create",
		Action:    command.ActionFunc(createAction),
		Usage:     "create certificate revocation list (CRL) for a given CA",
		UsageText: `**step crl create** <crl-file> [<revoked-serial> ...]`,
        Description: `**step crl create** produce a CRL file which last as longevity as the CA certificate.
The CRL will include all the revoked serial numbers passed as arguments.`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "ca",
				Usage: `The certificate authority used to issue the new certificate (PEM file).`,
			},
			cli.StringFlag{
				Name:  "ca-kms",
				Usage: "The <uri> to configure the KMS used for signing the certificate",
			},
			cli.StringFlag{
				Name:  "ca-key",
				Usage: `The certificate authority private key used to sign the new certificate (PEM file).`,
			},
			cli.StringFlag{
				Name:  "ca-password-file",
				Usage: `The path to the <file> containing the password to decrypt the CA private key.`,
			},
			cli.Int64Flag{
				Name:  "serial-number",
				Usage: `Serial number for the CRL. Must be a positive integer and monotonically increasing.`,
				Value: 1,
			},
		},
	}
}

func createAction(ctx *cli.Context) error {
	var (
		caCert         = ctx.String("ca")
		caKey          = ctx.String("ca-key")
		caKMS          = ctx.String("ca-kms")
		serialNumber   = ctx.Int64("serial-number")
		crlFile        = ctx.Args().First()
		revokedSerials = ctx.Args().Tail()
	)
	if caCert == "" {
		return errs.RequiredFlag(ctx, "ca")
	}
	if caKey == "" {
		return errs.RequiredFlag(ctx, "ca-key")
	}
	if serialNumber <= 0 {
		return errs.InvalidFlagValue(ctx, "serial-number", ctx.String("serial-number"), "must be a positive integer")
	}

	var opts []pemutil.Options
	if passFile := ctx.String("ca-password-file"); passFile != "" {
		opts = append(opts, pemutil.WithPasswordFile(passFile))
	}
	signer, err := cryptoutil.CreateSigner(caKMS, caKey, opts...)
	if err != nil {
		return err
	}
	cert, err := pemutil.ReadCertificate(caCert)
	if err != nil {
		return err
	}

	var revokedCertificates []x509.RevocationListEntry
	for _, revokedSerial := range revokedSerials {
		serial, ok := new(big.Int).SetString(revokedSerial, 10)
		if !ok {
			return errs.NewError("revoked serial number %q is not a valid integer", revokedSerial)
		}
		revokedCertificates = append(revokedCertificates, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: cert.NotBefore,
		})
	}

	var revocationList = &x509.RevocationList{
		Number:                    big.NewInt(serialNumber),
		RevokedCertificateEntries: revokedCertificates,
		ThisUpdate:                cert.NotBefore,
		NextUpdate:                cert.NotAfter,
	}
	revocationListBytes, err := x509.CreateRevocationList(rand.Reader, revocationList, cert, signer)
	if err != nil {
		return err
	}
	crlBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: revocationListBytes,
	})

	if err := fileutil.WriteFile(ctx.Args().First(), crlBytes, 0644); err != nil {
		return errs.FileError(err, crlFile)
	}
	_ = ui.Printf("CRL with serial number %d created and saved in %s\n", serialNumber, crlFile)

	return nil
}
