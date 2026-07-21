package admin

import "testing"

func TestFormatDisplayVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version string
		want    string
	}{
		{name: "release", version: "1.2.3", want: "v1.2.3"},
		{name: "prefixed release", version: "v1.2.3", want: "v1.2.3"},
		{name: "release candidate", version: "1.2.3-rc", want: "v1.2.3-RC"},
		{name: "uppercase release candidate", version: "v1.2.3-RC", want: "v1.2.3-RC"},
		{name: "development build", version: "dev", want: "dev"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := formatDisplayVersion(test.version); got != test.want {
				t.Errorf("formatDisplayVersion(%q) = %q, want %q", test.version, got, test.want)
			}
		})
	}
}
