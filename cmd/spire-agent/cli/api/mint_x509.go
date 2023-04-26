package api

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"

	"time"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"github.com/spiffe/spire/pkg/common/diskutil"
)

type mintCommand struct {
	printer   cliprinter.Printer
	env       *commoncli.Env
	serverId  string
	writePath string
}

type mintResult struct {
	X509SVID   [][]byte `json:"x509_svid"`
	PrivateKey []byte   `json:"private_key"`
	RootCAs    [][]byte `json:"root_cas"`
}

func NewMintCommand() cli.Command {
	return newMintCommand(commoncli.DefaultEnv, newWorkloadClient)
}

func newMintCommand(env *commoncli.Env, clientMaker workloadClientMaker) cli.Command {
	return adaptCommand(env, clientMaker, &mintCommand{env: env})
}

func (c *mintCommand) appendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.serverId, "serverId", "", "server id subject (optional)")
	fs.StringVar(&c.writePath, "write", "", "Write SVID data to the specified path (optional; only available for pretty output format)")
	outputValue := cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintX509)
	fs.Var(outputValue, "format", "deprecated; use -output")
}

func (c *mintCommand) name() string {
	return "mint a x509 svid"
}

func (c *mintCommand) synopsis() string {
	return "mint a x509 svid based on spiffeID"
}

func (c *mintCommand) run(ctx context.Context, env *commoncli.Env, client *workloadClient) error {
	//TODO: perhaps there's an another way to define the argument is required or optional
	if c.serverId == "" {
		return fmt.Errorf("server id is required")
	}

	fmt.Printf("yihsuanc: guid=%s\n", c.serverId)

	id, err := spiffeid.FromStringf("spiffe://example.org/testing/%s", c.serverId)
	if err != nil {
		return fmt.Errorf("cannot form a spiffe id")
	}

	fmt.Println("yihsuanc: (mint_x509.go MintX509SVID) preparing MintX509SVID")
	fmt.Printf("yihsuanc: ctx=%s\n", ctx)

	fmt.Printf("yihsuanc: mint_x509.go, run, %s\n", time.Now())
	fmt.Printf("yihsuanc: spiffeId=%s\n", id)
	svidResp, err := c.mintX509SVID(ctx, client, id.String())
	if err != nil {
		return err
	}

	if svidResp == nil {
		return fmt.Errorf("yihsuanc: empty! it is okay!")
	}

	if c.writePath == "" {
		return c.printer.PrintStruct(&mintResult{
			X509SVID:   svidResp.CertChain,
			PrivateKey: svidResp.PrivateKey,
			RootCAs:    svidResp.RootCAs,
		})
	}

	svidPEM, keyPEM, bundlePEM := convertSVIDResultToPEM(svidResp.CertChain, svidResp.PrivateKey, svidResp.RootCAs)

	svidPath := env.JoinPath(c.writePath, "svid.pem")
	keyPath := env.JoinPath(c.writePath, "key.pem")
	bundlePath := env.JoinPath(c.writePath, "bundle.pem")

	if err := diskutil.WritePubliclyReadableFile(svidPath, svidPEM.Bytes()); err != nil {
		return fmt.Errorf("unable to write SVID: %w", err)
	}

	if err := diskutil.WritePrivateFile(keyPath, keyPEM.Bytes()); err != nil {
		return fmt.Errorf("unable to write key: %w", err)
	}

	if err := diskutil.WritePrivateFile(bundlePath, bundlePEM.Bytes()); err != nil {
		return fmt.Errorf("unable to write bundle: %w", err)
	}

	return nil

}

func (c *mintCommand) mintX509SVID(ctx context.Context, client *workloadClient, spiffeId string) (*workload.MintX509SVIDResponse, error) {
	ctx, cancel := client.prepareContext(ctx)
	defer cancel()
	return client.MintX509SVID(ctx, &workload.MintX509SVIDRequest{
		SpiffeId: spiffeId,
	})
}

// TODO: add back printing after making sure connection is fine
func (c *mintCommand) prettyPrintX509(env *commoncli.Env, results ...interface{}) error {

	fmt.Println("yihsuanc: triggered prettyPrintX509")

	if resultInterface, ok := results[0].([]interface{}); ok {
		result, ok := resultInterface[0].(*mintResult)
		if !ok {
			return errors.New("unexpected type")
		}

		svidPEM, keyPEM, bundlePEM := convertSVIDResultToPEM(result.X509SVID, result.PrivateKey, result.RootCAs)

		if err := env.Printf("X509-SVID:\n%s\n", svidPEM.String()); err != nil {
			return err
		}
		if err := env.Printf("Private key:\n%s\n", keyPEM.String()); err != nil {
			return err
		}
		return env.Printf("Root CAs:\n%s\n", bundlePEM.String())

	}

	return cliprinter.ErrInternalCustomPrettyFunc

	// return nil
}

func convertSVIDResultToPEM(svidCertChain [][]byte, privateKey []byte, rootCAs [][]byte) (*bytes.Buffer, *bytes.Buffer, *bytes.Buffer) {
	svidPEM := new(bytes.Buffer)
	for _, certDER := range svidCertChain {
		_ = pem.Encode(svidPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})
	}

	keyPEM := new(bytes.Buffer)
	_ = pem.Encode(keyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKey,
	})

	bundlePEM := new(bytes.Buffer)
	for _, rootCA := range rootCAs {
		_ = pem.Encode(bundlePEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: rootCA,
		})
	}
	return svidPEM, keyPEM, bundlePEM
}
