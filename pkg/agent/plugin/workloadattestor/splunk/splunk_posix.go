package splunk

import (
	"bufio"
	"context"
	"fmt"

	// "fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/shirou/gopsutil/v3/process"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	// "github.com/spiffe/spire/pkg/common/util"
)

type Plugin struct {
	workloadattestorv1.UnsafeWorkloadAttestorServer
	configv1.UnsafeConfigServer

	mu     sync.Mutex
	config *Configuration
	log    hclog.Logger

	// hooks for tests
	hooks struct {
		newProcess      func(pid int32) (processInfo, error)
		lookupUserByID  func(id string) (*user.User, error)
		lookupGroupByID func(id string) (*user.Group, error)
	}
}

type processInfo interface {
	Uids() ([]int32, error)
	Gids() ([]int32, error)
	Groups() ([]string, error)
	Exe() (string, error)
	NamespacedExe() string
}

type Configuration struct {
	DiscoverWorkloadPath bool  `hcl:"discover_workload_path"`
	WorkloadSizeLimit    int64 `hcl:"workload_size_limit"`
}

type PSProcessInfo struct {
	*process.Process
}

func (ps PSProcessInfo) NamespacedExe() string {
	return getProcPath(ps.Pid, "exe")
}

func (ps PSProcessInfo) Groups() ([]string, error) {
	if runtime.GOOS != "linux" {
		return []string{}, nil
	}

	statusPath := getProcPath(ps.Pid, "status")

	f, err := os.Open(statusPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scnr := bufio.NewScanner(f)
	for scnr.Scan() {
		row := scnr.Text()
		parts := strings.SplitN(row, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(parts[0]))
		if key == "groups" {
			value := strings.TrimSpace(parts[1])
			return strings.Fields(value), nil
		}
	}

	if err := scnr.Err(); err != nil {
		return nil, err
	}

	return []string{}, nil
}

func getProcPath(pID int32, lastPath string) string {
	procPath := os.Getenv("HOST_PROC")
	if procPath == "" {
		procPath = "/proc"
	}
	return filepath.Join(procPath, strconv.FormatInt(int64(pID), 10), lastPath)
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		workloadattestorv1.WorkloadAttestorPluginServer(p),
		// configv1.ConfigServiceServer(p),
	)
}

func New() *Plugin {
	p := &Plugin{}
	p.hooks.newProcess = func(pid int32) (processInfo, error) { p, err := process.NewProcess(pid); return PSProcessInfo{p}, err }
	p.hooks.lookupUserByID = user.LookupId
	p.hooks.lookupGroupByID = user.LookupGroupId
	return p
}

// func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
// 	config := new(Configuration)
// 	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
// 		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
// 	}
// 	p.setConfig(config)
// 	return &configv1.ConfigureResponse{}, nil
// }

// for configv1.ConfigServiceServer(p),
// func (p *Plugin) setConfig(config *Configuration) {
// 	p.mu.Lock()
// 	p.config = config
// 	p.mu.Unlock()
// }

// for workloadattestorv1.WorkloadAttestorPluginServer(p),
func (p *Plugin) Attest(ctx context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	p.log.Warn("in splunk_posix.go Attest")
	// config, err := p.getConfig()
	// if err != nil {
	// 	return nil, err
	// }

	// proc, err := p.hooks.newProcess(req.Pid)
	// if err != nil {
	// 	return nil, status.Errorf(codes.Internal, "failed to get process: %v", err)
	// }

	var selectorValues []string
	selectorValues[0] = "testing"
	fmt.Println("added a testing value")

	// uid, err := p.getUID(proc)
	// if err != nil {
	// 	return nil, err
	// }
	// selectorValues = append(selectorValues, makeSelectorValue("uid", uid))

	// if user, ok := p.getUserName(uid); ok {
	// 	selectorValues = append(selectorValues, makeSelectorValue("user", user))
	// }

	// gid, err := p.getGID(proc)
	// if err != nil {
	// 	return nil, err
	// }
	// selectorValues = append(selectorValues, makeSelectorValue("gid", gid))

	// if group, ok := p.getGroupName(gid); ok {
	// 	selectorValues = append(selectorValues, makeSelectorValue("group", group))
	// }

	// sgIDs, err := proc.Groups()
	// if err != nil {
	// 	return nil, status.Errorf(codes.Internal, "supplementary GIDs lookup: %v", err)
	// }

	// for _, sgID := range sgIDs {
	// 	selectorValues = append(selectorValues, makeSelectorValue("supplementary_gid", sgID))

	// 	if sGroup, ok := p.getGroupName(sgID); ok {
	// 		selectorValues = append(selectorValues, makeSelectorValue("supplementary_group", sGroup))
	// 	}
	// }

	// // obtaining the workload process path and digest are behind a config flag
	// // since it requires the agent to have permissions that might not be
	// // available.
	// if config.DiscoverWorkloadPath {
	// 	processPath, err := p.getPath(proc)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	selectorValues = append(selectorValues, makeSelectorValue("path", processPath))

	// 	if config.WorkloadSizeLimit >= 0 {
	// 		exePath := p.getNamespacedPath(proc)
	// 		sha256Digest, err := util.GetSHA256Digest(exePath, config.WorkloadSizeLimit)
	// 		if err != nil {
	// 			return nil, status.Error(codes.Internal, err.Error())
	// 		}

	// 		selectorValues = append(selectorValues, makeSelectorValue("sha256", sha256Digest))
	// 	}
	// }

	return &workloadattestorv1.AttestResponse{
		SelectorValues: selectorValues,
	}, nil
}
