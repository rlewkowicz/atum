package update

func mapAt(value map[string]any, path ...string) map[string]any {
	current := value
	for _, key := range path {
		next, _ := current[key].(map[string]any)
		if next == nil {
			return map[string]any{}
		}
		current = next
	}
	return current
}

func stringAt(value map[string]any, path ...string) string {
	if len(path) == 0 {
		return ""
	}
	parent := mapAt(value, path[:len(path)-1]...)
	result, _ := parent[path[len(path)-1]].(string)
	return result
}

func mapSlice(value any) []map[string]any {
	raw, _ := value.([]any)
	result := make([]map[string]any, 0, len(raw))
	for _, entry := range raw {
		if object, ok := entry.(map[string]any); ok {
			result = append(result, object)
		}
	}
	return result
}
