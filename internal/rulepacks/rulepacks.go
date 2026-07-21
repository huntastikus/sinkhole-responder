// Package rulepacks provides curated, embedded collections of response rules.
package rulepacks

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/assets"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/rules"
	"gopkg.in/yaml.v3"
)

// Pack describes an available curated rulepack.
type Pack struct {
	Name        string
	Title       string
	Description string
	RuleCount   int
}

type packFile struct {
	Title       string       `yaml:"title"`
	Description string       `yaml:"description"`
	Rules       []rules.Rule `yaml:"rules"`
	Members     []string     `yaml:"members"`
}

//go:embed packs/*.yaml
var embeddedPacks embed.FS

var packFiles = mustLoadPacks()

// Available returns descriptions of all embedded packs, sorted by name.
func Available() []Pack {
	packs := make([]Pack, 0, len(packFiles))
	for name, file := range packFiles {
		count := len(file.Rules)
		for _, member := range file.Members {
			count += len(packFiles[member].Rules)
		}
		packs = append(packs, Pack{
			Name:        name,
			Title:       file.Title,
			Description: file.Description,
			RuleCount:   count,
		})
	}
	sort.Slice(packs, func(i, j int) bool {
		return packs[i].Name < packs[j].Name
	})
	return packs
}

// Merge returns user rules followed by the rules from enabled packs. Content
// packs are included at most once, including when expanded from a manifest.
func Merge(user []rules.Rule, enabled []string) ([]rules.Rule, error) {
	merged := make([]rules.Rule, len(user))
	copy(merged, user)
	added := make(map[string]bool)

	appendPack := func(name string) {
		if added[name] {
			return
		}
		merged = append(merged, packFiles[name].Rules...)
		added[name] = true
	}

	for _, name := range enabled {
		file, ok := packFiles[name]
		if !ok {
			return nil, fmt.Errorf("unknown rulepack %q", name)
		}
		if len(file.Members) == 0 {
			appendPack(name)
			continue
		}
		for _, member := range file.Members {
			appendPack(member)
		}
	}

	return merged, nil
}

func validateStubReferences(packRules []rules.Rule) error {
	for _, rule := range packRules {
		if _, ok := assets.Get(rule.Response.Embedded); !ok {
			return fmt.Errorf("rule %q references unknown embedded asset %q", rule.Name, rule.Response.Embedded)
		}
	}
	return nil
}

func mustLoadPacks() map[string]packFile {
	packs, err := loadPacks()
	if err != nil {
		panic(err)
	}
	return packs
}

func loadPacks() (map[string]packFile, error) {
	entries, err := fs.ReadDir(embeddedPacks, "packs")
	if err != nil {
		return nil, fmt.Errorf("read embedded rulepacks: %w", err)
	}

	packs := make(map[string]packFile, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		data, err := fs.ReadFile(embeddedPacks, "packs/"+entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read rulepack %q: %w", entry.Name(), err)
		}
		pack, err := parsePack(data)
		if err != nil {
			return nil, fmt.Errorf("parse rulepack %q: %w", entry.Name(), err)
		}
		name := strings.TrimSuffix(entry.Name(), ".yaml")
		packs[name] = pack
	}

	for name, pack := range packs {
		for _, member := range pack.Members {
			memberPack, ok := packs[member]
			if !ok {
				return nil, fmt.Errorf("rulepack %q references unknown member %q", name, member)
			}
			if len(memberPack.Members) != 0 {
				return nil, fmt.Errorf("rulepack %q references manifest member %q", name, member)
			}
		}
	}
	return packs, nil
}

func parsePack(data []byte) (packFile, error) {
	var pack packFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&pack); err != nil {
		return packFile{}, err
	}
	hasRules := len(pack.Rules) != 0
	hasMembers := len(pack.Members) != 0
	if hasRules == hasMembers {
		return packFile{}, fmt.Errorf("pack must define exactly one of rules or members")
	}
	if err := validateStubReferences(pack.Rules); err != nil {
		return packFile{}, err
	}
	return pack, nil
}
