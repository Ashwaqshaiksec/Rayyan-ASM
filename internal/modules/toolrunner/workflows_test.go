package toolrunner

import (
	"errors"
	"testing"

	"github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
	"go.uber.org/zap"
)

func newTestEngine(tools []types.ToolInfo) *WorkflowEngine {
	reg := types.NewRegistry()
	for _, t := range tools {
		reg.Register(t)
	}
	return NewWorkflowEngine(reg, zap.NewNop().Sugar())
}

func installedTool(name string, cat types.Category) types.ToolInfo {
	return types.ToolInfo{
		Name:     name,
		Category: cat,
		Status:   types.StatusInstalled,
		Enabled:  true,
	}
}

// --- unknown workflow ---

func TestRun_UnknownWorkflow_SetsError(t *testing.T) {
	e := newTestEngine(nil)
	result := e.Run("nonexistent_workflow", "example.com", nil)
	if result.Error == "" {
		t.Error("expected error for unknown workflow, got empty string")
	}
}

func TestRun_UnknownWorkflow_FinishedSet(t *testing.T) {
	e := newTestEngine(nil)
	result := e.Run("nonexistent_workflow", "example.com", nil)
	if result.Finished.IsZero() {
		t.Error("Finished should be set even on error")
	}
}

// --- no installed tools ---

func TestRun_DNSAssessment_NoTools_AllSkipped(t *testing.T) {
	// No tools registered → every stage skipped.
	e := newTestEngine(nil)
	result := e.Run(WorkflowDNSAssessment, "example.com", nil)
	if result.Error != "" {
		t.Errorf("unexpected error: %s", result.Error)
	}
	for _, s := range result.Stages {
		if s.Status != "skipped" {
			t.Errorf("expected skipped, got %s for stage %s", s.Status, s.Stage)
		}
	}
}

// --- stage execution ---

func TestRun_StageExecuted_OK(t *testing.T) {
	e := newTestEngine([]types.ToolInfo{
		installedTool("dnsx", types.CategoryDNS),
	})
	called := false
	stageFuncs := map[string]StageFunc{
		"dnsx": func(target string) (int, error) {
			called = true
			return 3, nil
		},
	}
	result := e.Run(WorkflowDNSAssessment, "example.com", stageFuncs)
	if !called {
		t.Error("expected dnsx stage func to be called")
	}
	if len(result.Stages) == 0 {
		t.Error("expected at least one stage result")
	}
	if result.Stages[0].Status != "ok" {
		t.Errorf("expected ok, got %s", result.Stages[0].Status)
	}
	if result.Stages[0].Count != 3 {
		t.Errorf("expected count=3, got %d", result.Stages[0].Count)
	}
}

func TestRun_StageExecuted_Error(t *testing.T) {
	e := newTestEngine([]types.ToolInfo{
		installedTool("dnsx", types.CategoryDNS),
	})
	stageFuncs := map[string]StageFunc{
		"dnsx": func(target string) (int, error) {
			return 0, errors.New("dns failure")
		},
	}
	result := e.Run(WorkflowDNSAssessment, "example.com", stageFuncs)
	if result.Stages[0].Status != "error" {
		t.Errorf("expected error status, got %s", result.Stages[0].Status)
	}
	if result.Stages[0].Error == "" {
		t.Error("expected Error field populated")
	}
}

func TestRun_NoExecutorForTool_Skipped(t *testing.T) {
	// Tool is installed but no StageFunc registered for it.
	e := newTestEngine([]types.ToolInfo{
		installedTool("dnsx", types.CategoryDNS),
	})
	result := e.Run(WorkflowDNSAssessment, "example.com", map[string]StageFunc{})
	if result.Stages[0].Status != "skipped" {
		t.Errorf("expected skipped when no executor, got %s", result.Stages[0].Status)
	}
}

// --- metadata ---

func TestRun_ResultContainsWorkflowAndTarget(t *testing.T) {
	e := newTestEngine(nil)
	result := e.Run(WorkflowDNSAssessment, "target.example.com", nil)
	if result.Workflow != WorkflowDNSAssessment {
		t.Errorf("expected workflow=%s, got %s", WorkflowDNSAssessment, result.Workflow)
	}
	if result.Target != "target.example.com" {
		t.Errorf("expected target=target.example.com, got %s", result.Target)
	}
}

func TestRun_StartedBeforeFinished(t *testing.T) {
	e := newTestEngine(nil)
	result := e.Run(WorkflowDNSAssessment, "example.com", nil)
	if result.Started.After(result.Finished) {
		t.Error("Started should not be after Finished")
	}
}

// --- RunAll flag ---

func TestRun_InjectionSuite_RunAllExecutesMultipleTools(t *testing.T) {
	e := newTestEngine([]types.ToolInfo{
		installedTool("sqlmap", types.CategoryInjection),
		installedTool("commix", types.CategoryInjection),
	})
	callCounts := map[string]int{}
	stageFuncs := map[string]StageFunc{
		"sqlmap": func(target string) (int, error) { callCounts["sqlmap"]++; return 1, nil },
		"commix": func(target string) (int, error) { callCounts["commix"]++; return 1, nil },
	}
	result := e.Run(WorkflowInjectionSuite, "example.com", stageFuncs)
	// InjectionSuite uses RunAll=true for CategoryInjection; both tools should run.
	if callCounts["sqlmap"]+callCounts["commix"] < 2 {
		t.Logf("stages: %+v", result.Stages)
		t.Error("expected both injection tools to execute with RunAll")
	}
}

// --- WorkflowType constants ---

func TestWorkflowTypeConstants_AllInStageMap(t *testing.T) {
	all := []WorkflowType{
		WorkflowExternalASM,
		WorkflowBugBounty,
		WorkflowInternalAssessment,
		WorkflowDNSAssessment,
		WorkflowWebAssessment,
		WorkflowWebFull,
		WorkflowAPIAudit,
		WorkflowJSRecon,
		WorkflowCMSDetect,
		WorkflowInjectionSuite,
		WorkflowGitSecrets,
		WorkflowTakeoverScan,
		WorkflowNucleiFullScan,
	}
	e := newTestEngine(nil)
	for _, wf := range all {
		result := e.Run(wf, "x.example.com", nil)
		if result.Error != "" {
			t.Errorf("workflow %s not in stage map: %s", wf, result.Error)
		}
	}
}
