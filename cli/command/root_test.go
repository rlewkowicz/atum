package command

import (
	"reflect"
	"testing"
)

func TestApproveAuxiliaryImageFlagPreservesEachTuple(t *testing.T) {
	t.Parallel()

	approvals := []string{
		"chart/operator=proxy,Apache-2.0,gcr.io/example/proxy:v1.0.0",
		"chart/scanner=helper,MIT,ghcr.io/example/helper:v2.0.0",
	}
	for _, test := range []struct {
		name string
		want []string
	}{
		{name: "one occurrence", want: approvals[:1]},
		{name: "repeated occurrences", want: approvals},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			command := (&app{}).pullCommand()
			updates, _, err := command.Find([]string{"updates"})
			if err != nil {
				t.Fatalf("find updates command: %v", err)
			}
			args := make([]string, 0, len(test.want)*2)
			for _, approval := range test.want {
				args = append(args, "--approve-auxiliary-image", approval)
			}
			if err := updates.ParseFlags(args); err != nil {
				t.Fatalf("parse approval flags: %v", err)
			}
			got, err := updates.Flags().GetStringArray("approve-auxiliary-image")
			if err != nil {
				t.Fatalf("read approval flags: %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("approval values = %#v, want %#v", got, test.want)
			}
		})
	}
}
