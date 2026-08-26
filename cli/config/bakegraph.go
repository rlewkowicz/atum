package config

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"atum/cli/fssecure"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	dockerfileparser "github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/zclconf/go-cty/cty"
)

type bakeGraph struct {
	variables map[string]cty.Value
	targets   map[string]bakeTarget
}

type bakeTarget struct {
	name       string
	context    string
	dockerfile string
	stage      string
	tags       []string
	contexts   map[string]string
	args       map[string]string
}

type parsedDockerfile struct {
	name   string
	stages []instructions.Stage
	byName map[string]int
}

func parseBakeGraph(data []byte, filename string) (*bakeGraph, error) {
	parsed, diagnostics := hclparse.NewParser().ParseHCL(data, filename)
	if diagnostics.HasErrors() {
		return nil, diagnostics
	}
	body, ok := parsed.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("unsupported HCL body %T", parsed.Body)
	}
	variables := make(map[string]cty.Value)
	templates := make(map[string]*hclsyntax.Block)
	for _, block := range body.Blocks {
		switch {
		case block.Type == "variable" && len(block.Labels) == 1:
			attribute, exists := block.Body.Attributes["default"]
			if !exists {
				continue
			}
			value, valueDiagnostics := attribute.Expr.Value(nil)
			if valueDiagnostics.HasErrors() || !value.IsKnown() {
				return nil, fmt.Errorf("variable %s has a non-static default", block.Labels[0])
			}
			variables[block.Labels[0]] = value
		case block.Type == "target" && len(block.Labels) == 1:
			label := block.Labels[0]
			if _, exists := templates[label]; exists {
				return nil, fmt.Errorf("target template %s is repeated", label)
			}
			templates[label] = block
		}
	}
	baseContext := &hcl.EvalContext{Variables: variables}
	graph := &bakeGraph{variables: variables, targets: make(map[string]bakeTarget, len(templates))}
	labels := make([]string, 0, len(templates))
	for label := range templates {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		block := templates[label]
		contexts, err := matrixContexts(block, baseContext)
		if err != nil {
			return nil, fmt.Errorf("target %s matrix: %w", label, err)
		}
		for _, evalContext := range contexts {
			target, err := resolveBakeTarget(label, templates, evalContext, make(map[string]bool))
			if err != nil {
				return nil, err
			}
			if target.name == "" {
				return nil, fmt.Errorf("target template %s resolves an empty name", label)
			}
			if _, exists := graph.targets[target.name]; exists {
				return nil, fmt.Errorf("target name %s is repeated", target.name)
			}
			graph.targets[target.name] = target
		}
	}
	return graph, nil
}

func matrixContexts(block *hclsyntax.Block, base *hcl.EvalContext) ([]*hcl.EvalContext, error) {
	attribute, exists := block.Body.Attributes["matrix"]
	if !exists {
		return []*hcl.EvalContext{base}, nil
	}
	value, diagnostics := attribute.Expr.Value(base)
	if diagnostics.HasErrors() || !value.IsKnown() || !value.CanIterateElements() {
		return nil, fmt.Errorf("must be a static object of finite collections")
	}
	matrix := value.AsValueMap()
	names := make([]string, 0, len(matrix))
	for name := range matrix {
		names = append(names, name)
	}
	sort.Strings(names)
	contexts := []*hcl.EvalContext{base.NewChild()}
	for _, name := range names {
		collection := matrix[name]
		if !collection.IsKnown() || !collection.CanIterateElements() {
			return nil, fmt.Errorf("dimension %s is not a finite collection", name)
		}
		values := make([]cty.Value, 0, collection.LengthInt())
		iterator := collection.ElementIterator()
		for iterator.Next() {
			_, item := iterator.Element()
			values = append(values, item)
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("dimension %s is empty", name)
		}
		next := make([]*hcl.EvalContext, 0, len(contexts)*len(values))
		for _, current := range contexts {
			for _, item := range values {
				child := current.NewChild()
				child.Variables = map[string]cty.Value{name: item}
				next = append(next, child)
			}
		}
		contexts = next
	}
	return contexts, nil
}

func resolveBakeTarget(label string, templates map[string]*hclsyntax.Block, ctx *hcl.EvalContext, stack map[string]bool) (bakeTarget, error) {
	block, exists := templates[label]
	if !exists {
		return bakeTarget{}, fmt.Errorf("Bake target inherits missing template %s", label)
	}
	if stack[label] {
		return bakeTarget{}, fmt.Errorf("Bake target inheritance contains a cycle at %s", label)
	}
	stack[label] = true
	defer delete(stack, label)
	result := bakeTarget{name: label, contexts: make(map[string]string), args: make(map[string]string)}
	if attribute, exists := block.Body.Attributes["inherits"]; exists {
		parents, err := evaluateStringList(attribute.Expr, ctx)
		if err != nil {
			return bakeTarget{}, fmt.Errorf("Bake target %s inherits: %w", label, err)
		}
		for _, parent := range parents {
			inherited, err := resolveBakeTarget(parent, templates, ctx, stack)
			if err != nil {
				return bakeTarget{}, err
			}
			mergeBakeTarget(&result, inherited)
			result.name = label
		}
	}
	for _, field := range []struct {
		name string
		set  func(string)
	}{
		{name: "name", set: func(value string) { result.name = value }},
		{name: "context", set: func(value string) { result.context = value }},
		{name: "dockerfile", set: func(value string) { result.dockerfile = value }},
		{name: "target", set: func(value string) { result.stage = value }},
	} {
		attribute, exists := block.Body.Attributes[field.name]
		if !exists {
			continue
		}
		value, err := evaluateString(attribute.Expr, ctx)
		if err != nil {
			return bakeTarget{}, fmt.Errorf("Bake target %s %s: %w", label, field.name, err)
		}
		field.set(value)
	}
	if attribute, exists := block.Body.Attributes["tags"]; exists {
		values, err := evaluateStringList(attribute.Expr, ctx)
		if err != nil {
			return bakeTarget{}, fmt.Errorf("Bake target %s tags: %w", label, err)
		}
		result.tags = values
	}
	for name, destination := range map[string]map[string]string{"contexts": result.contexts, "args": result.args} {
		attribute, exists := block.Body.Attributes[name]
		if !exists {
			continue
		}
		values, err := evaluateStringMap(attribute.Expr, ctx)
		if err != nil {
			return bakeTarget{}, fmt.Errorf("Bake target %s %s: %w", label, name, err)
		}
		for key, value := range values {
			destination[key] = value
		}
	}
	return result, nil
}

func mergeBakeTarget(destination *bakeTarget, source bakeTarget) {
	if source.context != "" {
		destination.context = source.context
	}
	if source.dockerfile != "" {
		destination.dockerfile = source.dockerfile
	}
	if source.stage != "" {
		destination.stage = source.stage
	}
	if len(source.tags) > 0 {
		destination.tags = append(destination.tags[:0], source.tags...)
	}
	for name, value := range source.contexts {
		destination.contexts[name] = value
	}
	for name, value := range source.args {
		destination.args[name] = value
	}
}

func evaluateString(expression hclsyntax.Expression, ctx *hcl.EvalContext) (string, error) {
	value, diagnostics := expression.Value(ctx)
	if diagnostics.HasErrors() || !value.IsKnown() || !value.Type().Equals(cty.String) {
		return "", fmt.Errorf("must resolve to a string")
	}
	return value.AsString(), nil
}

func evaluateStringList(expression hclsyntax.Expression, ctx *hcl.EvalContext) ([]string, error) {
	value, diagnostics := expression.Value(ctx)
	if diagnostics.HasErrors() || !value.IsKnown() || !value.CanIterateElements() {
		return nil, fmt.Errorf("must resolve to a string collection")
	}
	result := make([]string, 0, value.LengthInt())
	iterator := value.ElementIterator()
	for iterator.Next() {
		_, item := iterator.Element()
		if !item.IsKnown() || !item.Type().Equals(cty.String) {
			return nil, fmt.Errorf("contains a non-string value")
		}
		result = append(result, item.AsString())
	}
	return result, nil
}

func evaluateStringMap(expression hclsyntax.Expression, ctx *hcl.EvalContext) (map[string]string, error) {
	value, diagnostics := expression.Value(ctx)
	if diagnostics.HasErrors() || !value.IsKnown() || !value.CanIterateElements() {
		return nil, fmt.Errorf("must resolve to a string object")
	}
	result := make(map[string]string, value.LengthInt())
	iterator := value.ElementIterator()
	for iterator.Next() {
		key, item := iterator.Element()
		if !key.IsKnown() || !key.Type().Equals(cty.String) || !item.IsKnown() || !item.Type().Equals(cty.String) {
			return nil, fmt.Errorf("contains a non-string key or value")
		}
		result[key.AsString()] = item.AsString()
	}
	return result, nil
}

func (graph *bakeGraph) variableString(name string) string {
	value, exists := graph.variables[name]
	if !exists || !value.IsKnown() || !value.Type().Equals(cty.String) {
		return ""
	}
	return value.AsString()
}

func (graph *bakeGraph) validate(problems *[]string, policy DeliveryPolicy, roots []string) {
	for name := range graph.reachable(roots) {
		target, exists := graph.targets[name]
		if !exists {
			continue
		}
		if target.context != "." {
			*problems = append(*problems, fmt.Sprintf("Bake target %s must use the project root build context", name))
		}
		if target.dockerfile != "" {
			relative, err := fssecure.Relative(target.dockerfile)
			if err != nil || filepath.Dir(relative) != "docker" || !strings.HasPrefix(filepath.Base(relative), "Dockerfile") {
				*problems = append(*problems, fmt.Sprintf("Bake target %s Dockerfile path is invalid", name))
			}
		}
		for contextName, source := range target.contexts {
			if contextName == "" || strings.ContainsAny(contextName, "/\\:$") {
				*problems = append(*problems, fmt.Sprintf("Bake target %s has invalid context name %q", name, contextName))
				continue
			}
			switch {
			case strings.HasPrefix(source, "target:"):
				dependency := strings.TrimPrefix(source, "target:")
				if _, exists := graph.targets[dependency]; !exists {
					*problems = append(*problems, fmt.Sprintf("Bake target %s context %s references missing target %s", name, contextName, dependency))
				}
			case strings.HasPrefix(source, "docker-image://"):
				validatePinnedBuildMaterial(problems, policy, "Bake context "+name+"/"+contextName, strings.TrimPrefix(source, "docker-image://"))
			case strings.HasPrefix(source, "https://") && strings.Contains(source, ".git?"):
				checksum := queryValue(source, "checksum")
				if len(checksum) != 40 || !lowerHex(checksum) {
					*problems = append(*problems, fmt.Sprintf("Bake Git context %s/%s is not object-pinned: %s", name, contextName, source))
				}
			case source == "../.." && contextName == "atum_source" &&
				(name == "build-job" || name == "delivery-build-job"):
			default:
				*problems = append(*problems, fmt.Sprintf("Bake target %s context %s has unsupported source %q", name, contextName, source))
			}
		}
	}
}

func (graph *bakeGraph) reachable(roots []string) map[string]struct{} {
	reachable := make(map[string]struct{}, len(roots))
	pending := append([]string(nil), roots...)
	for len(pending) > 0 {
		last := len(pending) - 1
		name := pending[last]
		pending = pending[:last]
		if _, exists := reachable[name]; exists {
			continue
		}
		reachable[name] = struct{}{}
		target, exists := graph.targets[name]
		if !exists {
			continue
		}
		for _, source := range target.contexts {
			if dependency, found := strings.CutPrefix(source, "target:"); found {
				pending = append(pending, dependency)
			}
		}
	}
	return reachable
}

func (graph *bakeGraph) validateDeliveryTargets(problems *[]string, project *Project, files map[string][]byte) {
	validator := bakeTargetValidator{
		graph: graph, project: project, files: files,
		dockerfiles: make(map[string]*parsedDockerfile),
		visited:     make(map[string]bool), visiting: make(map[string]bool),
	}
	for _, image := range project.Desired.Delivery.Images {
		if name := image.Delivery.Default.BakeTarget; name != "" {
			validator.validateTarget(problems, name)
		}
	}
}

type bakeTargetValidator struct {
	graph       *bakeGraph
	project     *Project
	files       map[string][]byte
	dockerfiles map[string]*parsedDockerfile
	visited     map[string]bool
	visiting    map[string]bool
}

func (validator *bakeTargetValidator) validateTarget(problems *[]string, name string) {
	if validator.visited[name] {
		return
	}
	if validator.visiting[name] {
		*problems = append(*problems, fmt.Sprintf("Bake target dependency graph cycles at %s", name))
		return
	}
	target, exists := validator.graph.targets[name]
	if !exists {
		return
	}
	validator.visiting[name] = true
	defer delete(validator.visiting, name)
	dockerfile, err := validator.dockerfile(target.dockerfile)
	if err != nil {
		*problems = append(*problems, fmt.Sprintf("Bake target %s Dockerfile cannot be parsed: %v", name, err))
		return
	}
	stageIndex := len(dockerfile.stages) - 1
	if target.stage != "" {
		var found bool
		stageIndex, found = dockerfile.byName[strings.ToLower(target.stage)]
		if !found {
			*problems = append(*problems, fmt.Sprintf("Bake target %s references missing Dockerfile stage %s", name, target.stage))
			return
		}
	}
	validator.validateStage(problems, name, target, dockerfile, stageIndex, make(map[int]bool))
	validator.visited[name] = true
}

func (validator *bakeTargetValidator) dockerfile(relative string) (*parsedDockerfile, error) {
	if relative == "" {
		return nil, fmt.Errorf("no Dockerfile is configured")
	}
	if parsed, exists := validator.dockerfiles[relative]; exists {
		return parsed, nil
	}
	projectRelative := filepath.ToSlash(filepath.Join(filepath.Dir(buildGraphPath), relative))
	data, _, err := graphFile(validator.project, projectRelative, validator.files)
	if err != nil {
		return nil, err
	}
	result, err := dockerfileparser.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	stages, _, err := instructions.Parse(result.AST, nil)
	if err != nil {
		return nil, err
	}
	if len(stages) == 0 {
		return nil, fmt.Errorf("contains no stages")
	}
	parsed := &parsedDockerfile{name: filepath.Base(relative), stages: stages, byName: make(map[string]int, len(stages))}
	for index := range stages {
		if stages[index].Name != "" {
			parsed.byName[strings.ToLower(stages[index].Name)] = index
		}
	}
	validator.dockerfiles[relative] = parsed
	return parsed, nil
}

func (validator *bakeTargetValidator) validateStage(problems *[]string, targetName string, target bakeTarget, dockerfile *parsedDockerfile, index int, visited map[int]bool) {
	if index < 0 || index >= len(dockerfile.stages) || visited[index] {
		return
	}
	visited[index] = true
	stage := dockerfile.stages[index]
	validator.validateReference(problems, targetName, target, dockerfile, index, stage.BaseName, dockerfileLine(stage.Location), "FROM", visited)
	for _, command := range stage.Commands {
		switch typed := command.(type) {
		case *instructions.CopyCommand:
			if typed.From != "" {
				validator.validateReference(problems, targetName, target, dockerfile, index, typed.From, commandLine(command), "COPY --from", visited)
			}
		case *instructions.RunCommand:
			for _, mount := range instructions.GetMounts(typed) {
				if mount.From != "" {
					validator.validateReference(problems, targetName, target, dockerfile, index, mount.From, commandLine(command), "RUN --mount=from", visited)
				}
			}
		case *instructions.AddCommand:
			for _, source := range typed.SourcePaths {
				if strings.Contains(source, "$") {
					*problems = append(*problems, fmt.Sprintf("Dockerfile %s:%d target %s has dynamic ADD source %s", dockerfile.name, commandLine(command), targetName, source))
					continue
				}
				if !strings.Contains(source, "://") && !strings.HasPrefix(source, "git@") {
					continue
				}
				if !strings.HasPrefix(source, "https://") ||
					!strings.HasPrefix(typed.Checksum, "sha256:") ||
					!validHexSHA256(strings.TrimPrefix(typed.Checksum, "sha256:")) {
					*problems = append(*problems, fmt.Sprintf("Dockerfile %s:%d target %s has remote ADD %s without an exact SHA-256 checksum", dockerfile.name, commandLine(command), targetName, source))
				}
			}
		}
	}
}

func (validator *bakeTargetValidator) validateReference(problems *[]string, targetName string, target bakeTarget, dockerfile *parsedDockerfile, currentStage int, reference string, line int, instruction string, visited map[int]bool) {
	reference = expandBakeReference(reference, target.args)
	if reference == "scratch" || reference == validator.project.Desired.Delivery.Policy.BuildBase {
		return
	}
	if stage, err := strconv.Atoi(reference); err == nil {
		if stage < 0 || stage >= currentStage {
			*problems = append(*problems, fmt.Sprintf("Dockerfile %s:%d target %s %s references invalid stage %s", dockerfile.name, line, targetName, instruction, reference))
			return
		}
		validator.validateStage(problems, targetName, target, dockerfile, stage, visited)
		return
	}
	if stage, exists := dockerfile.byName[strings.ToLower(reference)]; exists {
		if stage >= currentStage {
			*problems = append(*problems, fmt.Sprintf("Dockerfile %s:%d target %s %s references non-prior stage %s", dockerfile.name, line, targetName, instruction, reference))
			return
		}
		validator.validateStage(problems, targetName, target, dockerfile, stage, visited)
		return
	}
	source, exists := target.contexts[reference]
	if !exists {
		*problems = append(*problems, fmt.Sprintf("Dockerfile %s:%d target %s %s uses external source %s outside its named contexts", dockerfile.name, line, targetName, instruction, reference))
		return
	}
	if dependency, isTarget := strings.CutPrefix(source, "target:"); isTarget {
		validator.validateTarget(problems, dependency)
	}
}

func expandBakeReference(reference string, args map[string]string) string {
	if strings.HasPrefix(reference, "${") && strings.HasSuffix(reference, "}") {
		if value, exists := args[strings.TrimSuffix(strings.TrimPrefix(reference, "${"), "}")]; exists {
			return value
		}
	}
	if strings.HasPrefix(reference, "$") {
		if value, exists := args[strings.TrimPrefix(reference, "$")]; exists {
			return value
		}
	}
	return reference
}

func dockerfileLine(location []dockerfileparser.Range) int {
	if len(location) == 0 {
		return 0
	}
	return location[0].Start.Line
}

func commandLine(command instructions.Command) int { return dockerfileLine(command.Location()) }
