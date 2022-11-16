package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

var (
	normalRule = `
rule TEST_RULE {
	meta:
		description = "Is a test rule"
	strings:
		$s = "test" ascii
	condition:
		all of them
}`
	badMetaRule = `
rule TEST_BAD_META_RULE {
	meta:
		description = "Is a bad meta test rule"
	meta:
		date = "2022-07-05"
}
`
	badConditionRule = `
rule TEST_BADCOND_RULE {
	meta:
		description = "Is a bad condition test rule"
	condition:
		all of them
	condition:
		any of them
}`
	externalVariableRuleInput = `
rule TEST_EXTVAR_RULE {
	meta:
		description = "Is an external variable test rule"
		filepath = "bin/ls"
	strings:
		$s = "test" ascii
	condition:
		all of them
}`
	externalVariableRuleOutput = `
rule TEST_EXTVAR_RULE {
	meta:
		description = "Is an external variable test rule"
		filepath = "bin/ls"
	strings:
		$s = "test" ascii
	condition:
		all of them and filepath matches /bin\/ls/
}`
)

func Test_initMagics(t *testing.T) {
	tests := []struct {
		name       string
		magics     string
		wantErr    bool
		wantMagics map[string]string
	}{
		{
			name:    "invalid file",
			wantErr: true,
		}, {
			name:    "Empty file",
			magics:  "",
			wantErr: true,
		}, {
			name:       "Just a comment",
			magics:     "# Test",
			wantErr:    false,
			wantMagics: map[string]string{},
		}, {
			name:       "Invalid token",
			magics:     "77;Test;Bad",
			wantErr:    false,
			wantMagics: map[string]string{},
		}, {
			name:       "Good magic",
			magics:     "4D 5A;EXE",
			wantErr:    false,
			wantMagics: map[string]string{"4D5A": "EXE"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.magics != "" {
				tmpFile, err := ioutil.TempFile(os.TempDir(), "magicstest-")
				if err != nil {
					t.Fatal("Cannot create temporary file", err)
				}
				defer os.Remove(tmpFile.Name())
				_, err = tmpFile.WriteString(tt.magics)
				if err != nil {
					t.Fatal("Cannot write into temporary file file", err)
				}
				*magicPathFlag = tmpFile.Name()
			}
			if err := initMagics(); (err != nil) != tt.wantErr {
				t.Errorf("initMagics() error = %v, wantErr %v", err, tt.wantErr)
			}
			if fmt.Sprint(tt.wantMagics) != fmt.Sprint(magics) {
				t.Errorf("initMagics() want = %v, got %v", tt.wantMagics, fmt.Sprint(magics))
			}
		})
	}
}

func Test_fungeRules(t *testing.T) {
	tests := []struct {
		name    string
		rule    string
		want    string
		wantErr bool
	}{
		{
			name:    "Empty file",
			rule:    "",
			want:    "",
			wantErr: false,
		}, {
			name:    "Normal rule",
			rule:    normalRule,
			want:    normalRule,
			wantErr: false,
		}, {
			name:    "Bad meta rule",
			rule:    badMetaRule,
			want:    "",
			wantErr: true,
		}, {
			name:    "Bad condition rule",
			rule:    badConditionRule,
			want:    "",
			wantErr: true,
		}, {
			name:    "Ext var rule",
			rule:    externalVariableRuleInput,
			want:    externalVariableRuleOutput,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := ioutil.TempFile(os.TempDir(), "fungetest-")
			if err != nil {
				t.Fatal("Cannot create temporary file", err)
			}
			defer os.Remove(tmpFile.Name())
			_, err = tmpFile.WriteString(tt.rule)
			if err != nil {
				t.Fatal("Cannot write into temporary file file", err)
			}
			got, err := fungeRules(tmpFile.Name())
			if (err != nil) != tt.wantErr {
				t.Errorf("fungeRules() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if strings.TrimSpace(got) != strings.TrimSpace(tt.want) {
				t.Errorf("fungeRules() = %v, want %v", got, tt.want)
			}
		})
	}
}
