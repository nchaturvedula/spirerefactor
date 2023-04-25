package api

import (
	"context"
	"flag"
	"fmt"

	"time"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

type mintCommand struct {
	printer  cliprinter.Printer
	env      *commoncli.Env
	spiffeID string
}

func NewMintCommand() cli.Command {
	return newMintCommand(commoncli.DefaultEnv, newWorkloadClient)
}

func newMintCommand(env *commoncli.Env, clientMaker workloadClientMaker) cli.Command {
	return adaptCommand(env, clientMaker, &mintCommand{env: env})
}

func (c *mintCommand) appendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.spiffeID, "spiffeID", "", "SPIFFE ID subject (optional)")
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
	_ = c.env.Println("mint x509 command is triggered.")
	fmt.Printf("yihsuanc: spiffeID=%s\n", c.spiffeID)

	fmt.Println("yihsuanc: (mint_x509.go MintX509SVID) preparing MintX509SVID")
	fmt.Printf("yihsuanc: ctx=%s\n", ctx)

	fmt.Printf("yihsuanc: mint_x509.go, run, %s\n", time.Now())
	svidResp, err := c.mintX509SVID(ctx, client)
	if err != nil {
		return err
	}

	if svidResp == nil {
		fmt.Println("yihsuanc: empty! it is okay!")
	}

	return nil
}

func (c *mintCommand) mintX509SVID(ctx context.Context, client *workloadClient) (*workload.MintX509SVIDResponse, error) {
	ctx, cancel := client.prepareContext(ctx)
	defer cancel()
	return client.MintX509SVID(ctx, &workload.MintX509SVIDRequest{
		SpiffeId: c.spiffeID,
	})
}

// TODO: add back printing after making sure connection is fine
func (c *mintCommand) prettyPrintX509(env *commoncli.Env, results ...interface{}) error {
	// resp, ok := results[0].(*workload.X509SVIDResponse)
	// if !ok {
	// 	return cliprinter.ErrInternalCustomPrettyFunc
	// }

	// svids, err := parseAndValidateX509SVIDResponse(resp)
	// if err != nil {
	// 	return err
	// }

	// if !c.silent {
	// 	printX509SVIDResponse(env, svids, c.respTime)
	// }

	// if c.writePath != "" {
	// 	if err := c.writeResponse(svids); err != nil {
	// 		return err
	// 	}
	// }

	return nil
}
