package rego

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"slices"
	"strings"

	fjson "github.com/open-policy-agent/eopa/pkg/json"
	"github.com/open-policy-agent/eopa/pkg/vm"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/ir"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	"github.com/open-policy-agent/opa/v1/util"
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
)

type EvalMode int

const (
	Rego EvalMode = iota
	IR
)

func (m EvalMode) String() string {
	switch m {
	case Rego:
		return "Rego"
	case IR:
		return "IR"
	default:
		return fmt.Sprintf("EvalMode(%d)", int(m))
	}
}

var checkTypesWithSubtype = set.New(types.SourceCloud, types.SourceDefsec, types.SourceKubernetes)

var supportedProviders = makeSupportedProviders()

func makeSupportedProviders() set.Set[string] {
	m := set.New[string]()
	for _, p := range providers.AllProviders() {
		m.Append(string(p))
	}
	m.Append("kind") // kubernetes
	return m
}

var _ options.ConfigurableScanner = (*Scanner)(nil)

type Scanner struct {
	ruleNamespaces           set.Set[string]
	policies                 map[string]*ast.Module
	moduleMetadata           map[string]*StaticMetadata
	store                    storage.Store
	runtimeValues            *ast.Term
	compiler                 *ast.Compiler
	regoErrorLimit           int
	logger                   *log.Logger
	traceWriter              io.Writer
	tracePerResult           bool
	retriever                *MetadataRetriever
	policyFS                 fs.FS
	policyDirs               []string
	policyReaders            []io.Reader
	dataFS                   fs.FS
	dataDirs                 []string
	frameworks               []framework.Framework
	includeDeprecatedChecks  bool
	includeEmbeddedPolicies  bool
	includeEmbeddedLibraries bool

	moduleFilters []RegoModuleFilter

	embeddedLibs   map[string]*ast.Module
	embeddedChecks map[string]*ast.Module
	customSchemas  map[string][]byte

	mode   EvalMode
	regoVM *vm.VM
}

func (s *Scanner) trace(heading string, input any) {
	if s.traceWriter == nil {
		return
	}
	// TODO: ident
	data, err := json.Marshal(input)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(s.traceWriter, "REGO %[1]s:\n%s\nEND REGO %[1]s\n\n", heading, string(data))
}

type DynamicMetadata struct {
	Warning   bool
	Filepath  string
	Message   string
	StartLine int
	EndLine   int
}

func unmarshalURL(dec *jsontext.Decoder, u *url.URL) error {
	if dec.PeekKind() != '"' {
		return json.SkipFunc
	}
	jval, err := dec.ReadValue()
	if err != nil {
		return err
	}

	parsed, err := url.Parse(string(jval)[1:len(jval)])
	if err != nil {
		return err
	}
	*u = *parsed
	return nil
}

func NewScanner(opts ...options.ScannerOption) *Scanner {
	s := &Scanner{
		regoErrorLimit: ast.CompileErrorLimitDefault,
		ruleNamespaces: builtinNamespaces.Clone(),
		runtimeValues:  addRuntimeValues(),
		logger:         log.WithPrefix("rego"),
		customSchemas:  make(map[string][]byte),
		moduleMetadata: make(map[string]*StaticMetadata),
		mode:           Rego,
	}

	for _, opt := range opts {
		opt(s)
	}

	switch s.mode {
	case IR:
		// TODO: handle errors
		policyBytes := lo.Must(os.ReadFile("/Users/nikita/projects/trivy-checks/bundle/ir/plan.json"))
		var irPolicy *ir.Policy
		lo.Must0(json.Unmarshal(policyBytes, &irPolicy))
		executable := lo.Must(vm.NewCompiler().WithPolicy(irPolicy).Compile())
		s.regoVM = vm.NewVM().WithExecutable(executable)

		annotationsBytes := lo.Must(os.ReadFile("/Users/nikita/projects/trivy-checks/bundle/ir/metadata.json"))
		var annotations map[string]*ast.Annotations
		lo.Must0(json.Unmarshal(annotationsBytes, &annotations,
			json.WithUnmarshalers(json.UnmarshalFromFunc(unmarshalURL))),
		)

		for modulePkg, annot := range annotations {
			moduleMeta, err := MetadataFromAnnotatins(modulePkg, annot)
			if err != nil {
				continue
			}
			s.moduleMetadata[modulePkg] = moduleMeta
		}
	case Rego:
		LoadAndRegister()
	}

	s.moduleFilters = append(
		s.moduleFilters,
		FrameworksFilter(s.frameworks),
		IncludeDeprecatedFilter(s.includeDeprecatedChecks),
	)

	return s
}

func (s *Scanner) runQuery(ctx context.Context, query string, input ast.Value, disableTracing bool) ([]any, []string, error) {

	trace := (s.traceWriter != nil || s.tracePerResult) && !disableTracing

	regoOptions := []func(*rego.Rego){
		rego.Query(query),
		rego.Compiler(s.compiler),
		rego.Store(s.store),
		rego.Runtime(s.runtimeValues),
		rego.Trace(trace),
	}

	if input != nil {
		regoOptions = append(regoOptions, rego.ParsedInput(input))
	}

	instance := rego.New(regoOptions...)
	resultSet, err := instance.Eval(ctx)
	if err != nil {
		return nil, nil, err
	}

	// we also build a slice of trace lines for per-result tracing - primarily for fanal/trivy
	var traces []string

	if trace {
		if s.traceWriter != nil {
			rego.PrintTrace(s.traceWriter, instance)
		}
		if s.tracePerResult {
			traceBuffer := bytes.NewBuffer([]byte{})
			rego.PrintTrace(traceBuffer, instance)
			traces = strings.Split(traceBuffer.String(), "\n")
		}
	}

	var rawResults []any
	for _, result := range resultSet {
		for _, expression := range result.Expressions {
			values, ok := expression.Value.([]any)
			if !ok {
				values = []any{expression.Value}
			}
			rawResults = append(rawResults, values...)
		}
	}
	return rawResults, traces, nil
}

func (s *Scanner) runPlan(ctx context.Context, name string, rawInput fjson.Json) ([]any, []string, error) {
	input := any(rawInput)
	evalResult, err := s.regoVM.Eval(ctx, name, vm.EvalOpts{
		Input:    &input,
		Seed:     rand.Reader,
		Cache:    builtins.Cache{},
		NDBCache: builtins.NDBCache{},
		Runtime:  s.runtimeValues.Value,
		Limits:   &vm.DefaultLimits,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("execute plan: %w", err)
	}

	resultJSON, err := ast.JSON(evalResult)
	if err != nil {
		return nil, nil, fmt.Errorf("convert Go value to JSON: %w", err)
	}

	results, err := extractResultArray(resultJSON)
	if err != nil {
		return nil, nil, err
	}
	return results, nil, nil
}

func extractResultArray(resultJSON any) ([]any, error) {
	resultsRaw, ok := resultJSON.([]any)
	if !ok || len(resultsRaw) == 0 {
		return nil, fmt.Errorf("unexpected result format: expected non-empty array")
	}

	firstItem, ok := resultsRaw[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected result format: first item is not a map")
	}

	resultField, ok := firstItem["result"]
	if !ok {
		return nil, fmt.Errorf("missing 'result' field in evaluation output")
	}

	results, ok := resultField.([]any)
	if !ok {
		return nil, fmt.Errorf("'result' field is not an array")
	}

	return results, nil
}

type Input struct {
	Path     string `json:"path"`
	FS       fs.FS  `json:"-"`
	Contents any    `json:"contents"`

	// parsedAst is the parsed input value for the Rego query
	parsedAst ast.Value

	// /parsedJson is the parsed input value used by eopa in IR mode
	parsedJson fjson.Json
}

func GetInputsContents(inputs []Input) []any {
	results := make([]any, len(inputs))
	for i, c := range inputs {
		results[i] = c.Contents
	}
	return results
}

func (s *Scanner) ScanInput(ctx context.Context, sourceType types.Source, inputs ...Input) (scan.Results, error) {

	s.logger.Debug("Scanning inputs", "count", len(inputs))

	if len(inputs) == 0 {
		return nil, nil
	}

	if s.mode == IR {
		// Necessary to avoid a panic from the VM
		_, ctx = vm.WithStatistics(ctx)
	}

	inputs = lo.FilterMap(inputs, func(input Input, _ int) (Input, bool) {
		s.trace("INPUT", input)

		var err error
		switch s.mode {
		case IR:
			var parsed fjson.Json
			do := vm.DataOperations{}
			parsed, err = do.FromInterface(context.Background(), input.Contents)
			if err == nil {
				input.parsedJson = parsed
			}
		case Rego:
			var parsedAst ast.Value
			parsedAst, err = parseRawInput(input.Contents)
			if err == nil {
				input.parsedAst = parsedAst
			}
		}

		if err != nil {
			s.logger.Error("Failed to parse input",
				log.FilePath(input.Path),
				log.Err(err),
				log.String("mode", s.mode.String()),
			)
			return input, false
		}

		return input, true
	})

	var results scan.Results

	for modulePkg, staticMeta := range s.moduleMetadata {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		namespace := strings.TrimPrefix(modulePkg, "data.")
		topLevel := strings.Split(namespace, ".")[0]
		if !s.ruleNamespaces.Contains(topLevel) {
			continue
		}

		// skip if check isn't relevant to what is being scanned
		if !isPolicyApplicable(sourceType, staticMeta, inputs...) {
			continue
		}

		evalRule := func(ruleName string) {
			ruleResults, err := s.applyRule(ctx, namespace, ruleName, inputs)
			if err != nil {
				s.logger.Error(
					"Error occurred while applying rule from check",
					log.String("rule", ruleName),
					log.String("package", modulePkg),
					log.Err(err),
				)
				return
			}
			results = append(results, s.embellishResultsWithRuleMetadata(ruleResults, *staticMeta)...)
		}

		switch s.mode {
		case IR:
			evalRule("deny")
		case Rego:
			module, exists := s.policies[modulePkg]
			if !exists {
				break
			}

			uniqueRules := set.New[string]()
			for _, rule := range module.Rules {
				name := rule.Head.Name.String()
				if !isEnforcedRule(name) {
					continue
				}
				uniqueRules.Append(name)
			}

			for ruleName := range uniqueRules.Iter() {
				evalRule(ruleName)
			}
		}
	}

	return results, nil
}

func (s *Scanner) metadataForModule(
	ctx context.Context, module *ast.Module, inputs []Input,
) (*StaticMetadata, error) {
	if metadata, exists := s.moduleMetadata[module.Package.Path.String()]; exists {
		return metadata, nil
	}

	metadata, err := s.retriever.RetrieveMetadata(ctx, module, GetInputsContents(inputs)...)
	if err != nil {
		return nil, err
	}
	return metadata, nil
}

func isPolicyWithSubtype(sourceType types.Source) bool {
	return checkTypesWithSubtype.Contains(sourceType)
}

func checkSubtype(ii map[string]any, provider string, subTypes []SubType) bool {
	if len(subTypes) == 0 {
		return true
	}

	for _, st := range subTypes {
		switch services := ii[provider].(type) {
		case map[string]any:
			if st.Provider != provider {
				continue
			}
			if _, exists := services[st.Service]; exists {
				return true
			}
		case string: // k8s - logic can be improved
			if strings.EqualFold(services, st.Group) ||
				strings.EqualFold(services, st.Version) ||
				strings.EqualFold(services, st.Kind) {
				return true
			}
		}
	}
	return false
}

var sourcesWithExplicitSelectors = []types.Source{
	// apply terrafrom-specific checks only if selectors exist
	types.SourceTerraformRaw,
}

func isPolicyApplicable(sourceType types.Source, staticMetadata *StaticMetadata, inputs ...Input) bool {
	if len(staticMetadata.InputOptions.Selectors) == 0 &&
		slices.Contains(sourcesWithExplicitSelectors, sourceType) {
		return false
	}

	if len(staticMetadata.InputOptions.Selectors) == 0 { // check always applies if no selectors
		return true
	}

	for _, selector := range staticMetadata.InputOptions.Selectors {
		if selector.Type != string(sourceType) {
			return false
		}
	}

	if !isPolicyWithSubtype(sourceType) {
		return true
	}

	for _, input := range inputs {
		if ii, ok := input.Contents.(map[string]any); ok {
			for provider := range ii {
				if !supportedProviders.Contains(provider) {
					continue
				}

				// check metadata for subtype
				for _, s := range staticMetadata.InputOptions.Selectors {
					if checkSubtype(ii, provider, s.Subtypes) {
						return true
					}
				}
			}
		}
	}
	return false
}

func parseRawInput(input any) (ast.Value, error) {
	if err := util.RoundTrip(&input); err != nil {
		return nil, err
	}

	return ast.InterfaceToValue(input)
}

func (s *Scanner) applyRule(ctx context.Context, namespace, rule string, inputs []Input) (scan.Results, error) {
	var results scan.Results
	query := fmt.Sprintf("data.%s.%s", namespace, rule)
	for _, input := range inputs {

		var (
			rawResults []any
			traces     []string
			err        error
		)

		switch s.mode {
		case Rego:
			rawResults, traces, err = s.runQuery(ctx, query, input.parsedAst, false)
		case IR:
			// Convert the Rego query into an IR entrypoint:
			// Rego uses dot notation with "data." prefix (e.g. data.aws.s3.bucket),
			// while the IR VM expects a slash-separated entrypoint without the prefix (e.g. aws/s3/bucket).
			entrypoint := strings.TrimPrefix(query, "data.")
			entrypoint = strings.ReplaceAll(entrypoint, ".", "/")
			rawResults, traces, err = s.runPlan(ctx, entrypoint, input.parsedJson)
		}

		if err != nil {
			return nil, err
		}

		s.trace("RESULTSET", rawResults)
		ruleResults := s.convertResults(rawResults, input, namespace, rule, traces)
		if len(ruleResults) == 0 { // It passed because we didn't find anything wrong (NOT because it didn't exist)
			var result regoResult
			result.FS = input.FS
			result.Filepath = input.Path
			result.Managed = true
			results.AddPassedRego(namespace, rule, traces, result)
			continue
		}
		results = append(results, ruleResults...)
	}

	return results, nil
}

// severity is now set with metadata, so deny/warn/violation now behave the same way
func isEnforcedRule(name string) bool {
	switch {
	case name == "deny", strings.HasPrefix(name, "deny_"):
		return true
	}
	return false
}
