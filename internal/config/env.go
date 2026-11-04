package config

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

const envPrefix = "AIRLOCK_"

// applyEnv sets scalar keys from AIRLOCK_ variables, with __ between levels.
func applyEnv(doc *yaml.Node, env Env) error {
	names := make([]string, 0, len(env))
	for name := range env {
		if strings.HasPrefix(name, envPrefix) && len(name) > len(envPrefix) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, name := range names {
		path := strings.Split(strings.ToLower(strings.TrimPrefix(name, envPrefix)), "__")
		if err := checkPath(reflect.TypeFor[Config](), path); err != nil {
			return fmt.Errorf("env %s: %w", name, err)
		}
		setScalar(doc, path, env[name])
	}
	return nil
}

func checkPath(t reflect.Type, path []string) error {
	for i, seg := range path {
		f, ok := fieldByTag(t, seg)
		if !ok {
			return fmt.Errorf("unknown key %s", strings.Join(path[:i+1], "."))
		}
		t = f.Type
		key := strings.Join(path[:i+1], ".")
		switch t.Kind() {
		case reflect.Slice, reflect.Map:
			return fmt.Errorf("cannot override list key %s", key)
		case reflect.Struct:
			if i == len(path)-1 {
				return fmt.Errorf("cannot override section %s", key)
			}
		default:
			if i != len(path)-1 {
				return fmt.Errorf("unknown key %s", strings.Join(path, "."))
			}
		}
	}
	return nil
}

func fieldByTag(t reflect.Type, name string) (reflect.StructField, bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if tag, _, _ := strings.Cut(f.Tag.Get("yaml"), ","); tag == name {
			return f, true
		}
	}
	return reflect.StructField{}, false
}

func setScalar(n *yaml.Node, path []string, value string) {
	for i, seg := range path {
		var child *yaml.Node
		for j := 0; j+1 < len(n.Content); j += 2 {
			if n.Content[j].Value == seg {
				child = n.Content[j+1]
				break
			}
		}
		last := i == len(path)-1
		if child == nil {
			child = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			if last {
				child = &yaml.Node{Kind: yaml.ScalarNode}
			}
			n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: seg}, child)
		}
		if last {
			child.Kind, child.Tag, child.Value, child.Style = yaml.ScalarNode, "", value, 0
			return
		}
		n = child
	}
}
