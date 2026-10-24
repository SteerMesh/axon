package templates

import (
	"bytes"
	"fmt"
	"os"

	"github.com/SteerMesh/axon/internal/domain"
	"gopkg.in/yaml.v3"
)

type Catalog struct {
	Templates map[string]Template `yaml:"templates"`
}

type Template struct {
	Target     string            `yaml:"target"`
	Args       []string          `yaml:"args"`
	Cwd        string            `yaml:"cwd"`
	Env        map[string]string `yaml:"env"`
	Permission domain.Permission `yaml:"permission"`
}

func Load(path string) (Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Catalog{}, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var catalog Catalog
	if err := decoder.Decode(&catalog); err != nil {
		return Catalog{}, fmt.Errorf("decode templates: %w", err)
	}
	for name, template := range catalog.Templates {
		if name == "" || template.Target == "" {
			return Catalog{}, fmt.Errorf("template names and targets are required")
		}
		switch template.Permission {
		case domain.PermissionInteractive, domain.PermissionReadOnly, domain.PermissionConfirmInput:
		default:
			return Catalog{}, fmt.Errorf("template %q has invalid permission %q", name, template.Permission)
		}
	}
	return catalog, nil
}

func (c Catalog) Resolve(name string) (domain.TargetSpec, domain.Permission, error) {
	template, ok := c.Templates[name]
	if !ok {
		return domain.TargetSpec{}, "", fmt.Errorf("template %q does not exist", name)
	}
	return domain.TargetSpec{
		Kind: template.Target, Args: append([]string(nil), template.Args...), Cwd: template.Cwd,
		Env: cloneMap(template.Env),
	}, template.Permission, nil
}

func cloneMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
