package rulepacks

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"git.kopenczei.net/arpad/sinkhole-responder/internal/assets"
	"git.kopenczei.net/arpad/sinkhole-responder/internal/rules"
)

func TestAvailable(t *testing.T) {
	got := Available()
	wantNames := []string{
		"adsense",
		"amazon-tam",
		"analytics",
		"anti-adblock",
		"cmp",
		"facebook",
		"gpt",
		"prebid",
		"recommended",
	}
	gotNames := make([]string, len(got))
	counts := make(map[string]int, len(got))
	for i, pack := range got {
		gotNames[i] = pack.Name
		counts[pack.Name] = pack.RuleCount
		if pack.Title == "" {
			t.Errorf("pack %q has an empty title", pack.Name)
		}
		if pack.Description == "" {
			t.Errorf("pack %q has an empty description", pack.Name)
		}
		if pack.RuleCount <= 0 {
			t.Errorf("pack %q has non-positive rule count %d", pack.Name, pack.RuleCount)
		}
	}
	if !slices.Equal(gotNames, wantNames) {
		t.Fatalf("Available() names = %v, want %v", gotNames, wantNames)
	}

	wantRecommended := counts["adsense"] + counts["gpt"] + counts["analytics"] + counts["facebook"] + counts["amazon-tam"]
	if counts["recommended"] != wantRecommended {
		t.Errorf("recommended RuleCount = %d, want member sum %d", counts["recommended"], wantRecommended)
	}
}

func TestMergeUserOnlyReturnsIndependentCopy(t *testing.T) {
	user := []rules.Rule{{Name: "user-rule", Host: "example.com"}}

	got, err := Merge(user, nil)
	if err != nil {
		t.Fatalf("Merge() error = %v", err)
	}
	if !reflect.DeepEqual(got, user) {
		t.Fatalf("Merge() = %#v, want %#v", got, user)
	}
	got[0].Name = "changed"
	if user[0].Name != "user-rule" {
		t.Fatal("Merge() result aliases the input slice")
	}
}

func TestMergeKeepsUserRulesBeforePackRules(t *testing.T) {
	user := []rules.Rule{{
		Name:     "user-adsense",
		Host:     "pagead2.googlesyndication.com",
		PathGlob: "**/adsbygoogle.js",
	}}

	got, err := Merge(user, []string{"adsense"})
	if err != nil {
		t.Fatalf("Merge() error = %v", err)
	}
	if len(got) < 2 {
		t.Fatalf("Merge() returned %d rules, want user and pack rules", len(got))
	}
	if got[0].Name != "user-adsense" {
		t.Errorf("first rule = %q, want user rule", got[0].Name)
	}
	if got[1].Host != user[0].Host || got[1].PathGlob != user[0].PathGlob {
		t.Errorf("first pack rule match = %q %q, want %q %q", got[1].Host, got[1].PathGlob, user[0].Host, user[0].PathGlob)
	}
}

func TestMergeRecommendedExpandsMembersAndDeduplicates(t *testing.T) {
	members := []string{"adsense", "gpt", "analytics", "facebook", "amazon-tam"}
	wantNames := make(map[string]struct{})
	for _, member := range members {
		merged, err := Merge(nil, []string{member})
		if err != nil {
			t.Fatalf("Merge(%q) error = %v", member, err)
		}
		for _, rule := range merged {
			wantNames[rule.Name] = struct{}{}
		}
	}

	recommended, err := Merge(nil, []string{"recommended"})
	if err != nil {
		t.Fatalf("Merge(recommended) error = %v", err)
	}
	gotNames := make(map[string]struct{}, len(recommended))
	for _, rule := range recommended {
		gotNames[rule.Name] = struct{}{}
	}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Errorf("recommended rule names = %v, want member union %v", gotNames, wantNames)
	}

	withDirectMember, err := Merge(nil, []string{"recommended", "adsense"})
	if err != nil {
		t.Fatalf("Merge(recommended, adsense) error = %v", err)
	}
	if len(withDirectMember) != len(recommended) {
		t.Errorf("Merge(recommended, adsense) returned %d rules, want %d", len(withDirectMember), len(recommended))
	}
}

func TestMergeUnknownPack(t *testing.T) {
	if _, err := Merge(nil, []string{"nope"}); err == nil {
		t.Fatal("Merge() error = nil, want unknown-pack error")
	}
}

func TestPackStubReferencesExist(t *testing.T) {
	ruleNames := make(map[string]string)
	for name, pack := range packFiles {
		t.Run(name, func(t *testing.T) {
			if err := validateStubReferences(pack.Rules); err != nil {
				t.Fatalf("validateStubReferences() error = %v", err)
			}
			if _, err := rules.Compile(pack.Rules, ""); err != nil {
				t.Fatalf("rules.Compile() error = %v", err)
			}
			for _, rule := range pack.Rules {
				if previousPack, exists := ruleNames[rule.Name]; exists {
					t.Errorf("rule name %q is duplicated in packs %q and %q", rule.Name, previousPack, name)
				}
				ruleNames[rule.Name] = name
				if _, ok := assets.Get(rule.Response.Embedded); !ok {
					t.Errorf("rule %q references unknown asset %q", rule.Name, rule.Response.Embedded)
				}
			}
		})
	}
}

func TestParsePackRequiresRulesXORMembers(t *testing.T) {
	tests := map[string]string{
		"both":    "title: Both\ndescription: invalid\nrules:\n  - name: one\n    host: example.com\n    response:\n      embedded: empty-js\nmembers: [adsense]\n",
		"neither": "title: Neither\ndescription: invalid\n",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePack([]byte(input)); err == nil {
				t.Fatal("parsePack() error = nil, want rules-xor-members error")
			}
		})
	}
}

func TestParsePackRejectsUnknownFields(t *testing.T) {
	tests := map[string]string{
		"pack":     "title: Test\ndescription: Test\nrules:\n  - host: example.com\nunknown_pack: true\n",
		"rule":     "title: Test\ndescription: Test\nrules:\n  - host: example.com\n    unknown_rule: true\n",
		"response": "title: Test\ndescription: Test\nrules:\n  - host: example.com\n    response:\n      unknown_response: true\n",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := parsePack([]byte(input))
			if err == nil || !strings.Contains(err.Error(), "field unknown_"+name+" not found") {
				t.Fatalf("parsePack() error = %v, want yaml.v3 unknown-field error", err)
			}
		})
	}
}
