package main

/*
Copyright 2022 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.

You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/hillu/go-yara/v4"
)

// Scanner is an instance of the Yara scanner.
type Scanner struct {
	rulesPath string
	Rules     *yara.Rules
}

// Detection contains the information to report a Yara detection.
type Detection struct {
	ImagePath   string
	SHA256      string
	Signature   string
	Description string
	Reference   string
	Score       int
}

var (
	scanner           Scanner
	maxMagics         int
	scanPathFlag      = flag.String("folder", "", "Specify a particular folder to be scanned")
	rulePathFlag      = flag.String("rules", "", "Specify a particular path to a file or folder containing the Yara rules to use")
	magicPathFlag     = flag.String("magic", "misc/file-type-signatures.txt", "A path under the rules path that contains File Magics")
	yaraRulesFlag     = flag.String("extrayara", "", "Any additional Yara rules to be used")
	testRulesFlag     = flag.Bool("testrules", false, "Test the given rules for syntax validity and then exit")
	minScoreFlag      = flag.Int("minscore", 40, "Only rules with scores greater than this will be output")
	magics            = make(map[string]string)
	externalVariables = []string{"filepath", "filename", "filetype", "extension", "owner"}
	maxGoroutines     = 10
	maxScanFilesize   = 1073741824 /* 1 Gb */
)

func initMagics() error {
	// Try magic:
	file, err := os.Open(*magicPathFlag) // For read access.
	if err != nil {
		// Try rule + magic
		file, err = os.Open(path.Join(*rulePathFlag, *magicPathFlag))
		if err != nil {
			return fmt.Errorf("unable to open Magics file: %v", err)
		}
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		t := scanner.Text()
		if strings.HasPrefix(t, "#") || strings.TrimSpace(t) == "" {
			continue
		}
		tokens := strings.Split(t, ";")
		if len(tokens) != 2 {
			log.Printf("Unable to parse: %v", t)
			continue
		}
		sig := strings.Replace(tokens[0], " ", "", -1)
		if len(sig) > maxMagics {
			maxMagics = len(sig)
		}
		magics[sig] = tokens[1]
	}
	return nil
}

func getFileTypes(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("error opening file: %v", err)
	}
	defer f.Close()
	fData := make([]byte, maxMagics)
	f.Read(fData)
	for k, v := range magics {
		sig, err := hex.DecodeString(k)
		if err != nil {
			log.Printf("Unable to parse signature %v: %v\n", k, err)
			continue
		}
		if bytes.Equal(fData[:len(sig)], sig) {
			return v, nil
		}
	}
	return "UNKNOWN", nil
}

func sha256sum(filePath string) (string, error) {
	h := sha256.New()
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	_, err = io.Copy(h, file)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func newDetection(imagePath, signature, description, reference string, score int) *Detection {
	sha256, err := sha256sum(imagePath)
	if err != nil {
		log.Printf("Unable to hash file %v: %v\n", imagePath, err)
	}

	return &Detection{
		ImagePath:   imagePath,
		SHA256:      sha256,
		Signature:   signature,
		Description: description,
		Reference:   reference,
		Score:       score,
	}
}

func fungeRules(filePath string) (string, error) {
	var ret []string
	var meta, condition bool
	var filepath, filename, filetype, not, extension, owner string

	rulesFile, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer rulesFile.Close()
	scanner := bufio.NewScanner(rulesFile)
	for scanner.Scan() {
		t := scanner.Text()
		trimmedT := strings.TrimSpace(t)
		if trimmedT == "" {
			continue
		}
		if meta && trimmedT != "meta:" && strings.HasSuffix(trimmedT, ":") {
			meta = false
		}
		if meta {
			switch {
			case strings.HasPrefix(trimmedT, "filename = "):
				tokens := strings.Split(t, " ")
				filename = strings.Replace(tokens[len(tokens)-1], `"`, "", -1)
			case strings.HasPrefix(trimmedT, "filepath = "):
				tokens := strings.Split(t, " ")
				filepath = strings.Replace(tokens[len(tokens)-1], `"`, "", -1)
			case strings.HasPrefix(trimmedT, "filetype = "):
				tokens := strings.Split(t, " ")
				filetype = strings.Replace(tokens[len(tokens)-1], `"`, "", -1)
			case strings.HasPrefix(trimmedT, "extension = "):
				tokens := strings.Split(t, " ")
				extension = strings.Replace(tokens[len(tokens)-1], `"`, "", -1)
			case strings.HasPrefix(trimmedT, "owner = "):
				tokens := strings.Split(t, " ")
				owner = strings.Replace(tokens[len(tokens)-1], `"`, "", -1)
			}
		}
		if trimmedT == "meta:" {
			if meta {
				return "", fmt.Errorf("error funging Yara rule: was in meta section and met meta section header")
			}
			meta = true
		}
		if condition && trimmedT != "condition:" && strings.HasSuffix(trimmedT, ":") {
			condition = false
		}
		if condition && !strings.HasSuffix(trimmedT, ":") {
			if filepath != "" {
				if filepath[0] == '!' {
					not = "not "
					filepath = filepath[1:]
				}
				t = t + fmt.Sprintf(" and %vfilepath matches /%v/", not, strings.ReplaceAll(filepath, `/`, `\/`))
				filepath = ""
				not = ""
			}
			if filename != "" {
				if filename[0] == '!' {
					not = "not "
					filename = filename[1:]
				}
				t = t + fmt.Sprintf(" and %vfilename matches /%v/", not, strings.ReplaceAll(filename, `/`, `\/`))
				filename = ""
				not = ""
			}
			if filetype != "" {
				if filetype[0] == '!' {
					not = "not "
					filetype = filetype[1:]
				}
				t = t + fmt.Sprintf(` and %vfiletype == "%v"`, not, filetype)
				filetype = ""
				not = ""
			}
			if extension != "" {
				if extension[0] == '!' {
					not = "not "
					extension = extension[1:]
				}
				if !strings.HasPrefix(extension, ".") {
					extension = "." + extension
				}
				t = t + fmt.Sprintf(` and %vextension == "%v"`, not, extension)
				extension = ""
				not = ""
			}
			if owner != "" {
				if owner[0] == '!' {
					not = "not "
					owner = owner[1:]
				}
				t = t + fmt.Sprintf(` and %vowner == "%v"`, not, owner)
				owner = ""
				not = ""
			}
		}
		if trimmedT == "condition:" {
			if condition {
				return "", fmt.Errorf("error funging Yara rule: was in condition section and met condition header")
			}
			condition = true
		}
		ret = append(ret, t)
	}
	return strings.Join(ret, "\n"), nil
}

// Compile will compile the provided Yara rules in a Rules struct.
func (s *Scanner) compile() error {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return err
	}
	for _, v := range externalVariables {
		compiler.DefineVariable(v, "")
	}

	rulesStat, err := os.Stat(s.rulesPath)
	if err != nil {
		return err
	}
	switch mode := rulesStat.Mode(); {
	case mode.IsDir():
		err = filepath.Walk(s.rulesPath, func(filePath string, fileInfo os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			fileName := fileInfo.Name()

			// Check if the file has extension .yar or .yara.
			if (path.Ext(fileName) == ".yar") || (path.Ext(fileName) == ".yara") {
				// Open the rule file and add it to the Yara compiler.
				r, err := fungeRules(filePath)
				if err != nil {
					return fmt.Errorf("unable to funge rules %v: %v", filePath, err)
				}
				err = compiler.AddString(r, "")
				if err != nil {
					return fmt.Errorf("unable to parse rule %v: %v", filePath, err)
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("error walking the path %v", err)
		}
	case mode.IsRegular():
		r, err := fungeRules(s.rulesPath)
		if err != nil {
			return fmt.Errorf("unable to funge rules %v: %v", s.rulesPath, err)
		}
		err = compiler.AddString(r, "")
		if err != nil {
			return fmt.Errorf("unable to compile rules: %v", err)
		}
	}

	if *yaraRulesFlag != "" {
		r, err := fungeRules(*yaraRulesFlag)
		if err != nil {
			return fmt.Errorf("unable to funge parameterised rules: %v", err)
		}
		err = compiler.AddString(r, "")
		if err != nil {
			return fmt.Errorf("error adding rule from parameter: %v", err)
		}
	}

	// Collect and compile Yara rules.
	s.Rules, err = compiler.GetRules()
	if err != nil {
		return err
	}

	return nil
}

func (s *Scanner) init() error {
	if *rulePathFlag != "" {
		if _, err := os.Stat(*rulePathFlag); os.IsNotExist(err) {
			return errors.New("the specified rules path does not exist")
		}
		s.rulesPath = *rulePathFlag
		return s.compile()
	}
	return errors.New("no rulepath given")
}

func filesystemScan(wait chan struct{}, c chan *Detection, minimumScore int) {
	defer close(c)
	if _, err := os.Stat(*scanPathFlag); err != nil {
		log.Printf("Cannot scan %v: %v\n", *scanPathFlag, err)
		return
	}
	var wg sync.WaitGroup
	err := filepath.Walk(*scanPathFlag, func(filePath string, fileInfo os.FileInfo, err error) error {
		if !fileInfo.Mode().IsRegular() {
			return nil
		}

		wg.Add(1)
		wait <- struct{}{}
		go func() {
			defer wg.Done()
			if fileInfo.Size() <= int64(maxScanFilesize) {
				matches, _ := scanFile(scanner, filePath, fileInfo)
				for _, match := range matches {
					var description, reference string
					score := 50
					for _, m := range match.Metas {
						var parsedScore int
						if m.Identifier == "score" {
							switch g := m.Value.(type) {
							case int:
								parsedScore = m.Value.(int)
							case string:
								parsedScore, err = strconv.Atoi(strings.TrimSpace(m.Value.(string)))
								if err != nil {
									parsedScore = 50
								}
							default:
								log.Printf("Unable to parse score for rule %v (type %v)): %v\n", match.Rule, g, m)
							}
							score = parsedScore
						}
						if strings.HasPrefix(m.Identifier, "desc") {
							description = m.Value.(string)
						}
						if m.Identifier == "reference" || strings.HasPrefix(m.Identifier, "report") {
							reference = m.Value.(string)
						}
						if m.Identifier == "context" {
							v := strings.ToLower(m.Value.(string))
							if v == "yes" || v == "true" || v == "1" {
								score = 0
							}
						}
					}
					if score > minimumScore {
						c <- newDetection(filePath, match.Rule, description, reference, score)
					}
				}
			}
			<-wait
		}()
		return nil
	})
	if err != nil {
		log.Printf("Error walking dir: %v\n", err)
	}
	wg.Wait()
}

func scanFile(s Scanner, filePath string, fileInfo os.FileInfo) (yara.MatchRules, error) {
	var matches yara.MatchRules

	ys, err := yara.NewScanner(s.Rules)
	if err != nil {
		return nil, fmt.Errorf("unable to load scanner: %v", err)
	}

	// Fill the variables
	ys.DefineVariable("filepath", filePath)
	ys.DefineVariable("filename", fileInfo.Name())
	ys.DefineVariable("extension", filepath.Ext(filePath))

	stat := fileInfo.Sys().(*syscall.Stat_t)
	// TODO: Read this in from mounted /etc/passwd if we have it.
	owner, err := user.LookupId(strconv.FormatUint(uint64(stat.Uid), 10))
	if err == nil {
		ys.DefineVariable("owner", owner.Username)
	}

	ft, err := getFileTypes(filePath)
	if err != nil {
		log.Printf("Unable to determine file type of file %v: %v\n", filePath, err)
	}
	ys.DefineVariable("filetype", ft)

	// Scan the file.
	f, err := os.Open(filePath)
	if err != nil {
		log.Printf("Unable to open file %v: %v\n", filePath, err)
	}
	err = ys.SetCallback(&matches).ScanFileDescriptor(f.Fd())

	if err != nil {
		return matches, err
	}

	// Return any results.
	return matches, nil
}

func main() {
	flag.Parse()

	if (!*testRulesFlag && *scanPathFlag == "") || *rulePathFlag == "" {
		log.Println("Usage: fraken -folder <path to scan> -rules <path to rules> [-magic <path to magics>] [-extrayara <path to file>] [-testrules]")
		os.Exit(1)
	}
	if err := scanner.init(); err != nil {
		log.Fatalf("Error initialising Yara engine: %v\n", err)
	}
	if *testRulesFlag {
		log.Println("Rules test OK")
		os.Exit(0)
	}
	if err := initMagics(); err != nil {
		log.Println("Error initialising Magic file (continuing without it): ", err)
	}
	waitChan := make(chan struct{}, maxGoroutines)
	resultsChan := make(chan *Detection)
	go filesystemScan(waitChan, resultsChan, *minScoreFlag)
	var results []*Detection
	for r := range resultsChan {
		results = append(results, r)
	}
	if len(results) == 0 {
		log.Println("No hits")
		os.Exit(0)
	}
	j, err := json.Marshal(results)
	if err != nil {
		log.Printf("Error marshalling JSON: %v", err)
	} else {
		fmt.Println(string(j))
	}
}
