package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
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
	Score       string
}

var (
	scanner           Scanner
	scanPathFlag      *string
	rulePathFlag      *string
	magicPathFlag     *string
	yaraRulesFlag     *string
	magics            = make(map[string]string)
	maxMagics         int
	externalVariables = []string{"filepath", "filename", "filetype", "extension", "owner"}
	MAX_GOROUTINES    = 10
)

func initMagics() {
	// Try magic:
	file, err := os.Open("file.go") // For read access.
	if err != nil {
		// Try rule + magic
		file, err = os.Open(path.Join(*rulePathFlag, *magicPathFlag))
		if err != nil {
			fmt.Printf("unable to open Magics file: %v\n", err)
			return
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
}

func getFileTypes(filePath string) string {
	f, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return ""
	}
	defer f.Close()
	fData := make([]byte, maxMagics)
	f.Read(fData)
	for k, v := range magics {
		sig, err := hex.DecodeString(k)
		if err != nil {
			fmt.Printf("Unable to parse signature %v: %v\n", k, err)
			continue
		}
		if bytes.Equal(fData[:len(sig)], sig) {
			return v
		}
	}
	return "UNKNOWN"
}

func hashFile(filePath string) (string, error) {
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

func newDetection(imagePath, signature, description, reference, score string) *Detection {
	sha256, _ := hashFile(imagePath)

	return &Detection{
		ImagePath:   imagePath,
		SHA256:      sha256,
		Signature:   signature,
		Description: description,
		Reference:   reference,
		Score:       score,
	}
}

func fungeRules(filePath string) string {
	var ret []string
	var meta bool
	var condition bool
	var filepath string
	var filename string
	var filetype string
	var not string
	var extension string
	var owner string

	rulesFile, _ := os.Open(filePath)
	defer rulesFile.Close()
	scanner := bufio.NewScanner(rulesFile)
	for scanner.Scan() {
		t := scanner.Text()
		trimmedT := strings.TrimSpace(t)
		if trimmedT == "" {
			continue
		}
		if meta && strings.HasSuffix(trimmedT, ":") {
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
				log.Fatal("Was in meta and met meta")
			}
			meta = true
		}
		if condition {
			if filepath != "" {
				if filepath[0] == '!' {
					not = "not "
					filepath = filepath[1:]
				}
				t = t + fmt.Sprintf(" and %vfilepath matches /%v/", not, filepath)
				filepath = ""
				not = ""
			}
			if filename != "" {
				if filename[0] == '!' {
					not = "not "
					filename = filename[1:]
				}
				t = t + fmt.Sprintf(" and %vfilename matches /%v/", not, filename)
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
			condition = false
		}
		if trimmedT == "condition:" {
			if condition {
				log.Fatal("Was in condition and met condition")
			}
			condition = true
		}
		ret = append(ret, t)
	}
	return strings.Join(ret, "\n")
}

// Compile will compile the provided Yara rules in a Rules object.
func (s *Scanner) compile() error {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return err
	}
	for _, v := range externalVariables {
		compiler.DefineVariable(v, "")
	}

	rulesStat, _ := os.Stat(s.rulesPath)
	switch mode := rulesStat.Mode(); {
	case mode.IsDir():
		err = filepath.Walk(s.rulesPath, func(filePath string, fileInfo os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			fileName := fileInfo.Name()

			// Check if the file has extension .yar or .yara.
			if (path.Ext(fileName) == ".yar") || (path.Ext(fileName) == ".yara") {
				// log.Println("Adding rule ", filePath)

				// Open the rule file and add it to the Yara compiler.
				err = compiler.AddString(fungeRules(filePath), "")
				if err != nil {
					log.Fatalf("Unable to parse rule: %v", err)
				}
			}
			return nil
		})
		if err != nil {
			fmt.Printf("error walking the path %v\n", err)
			return err
		}
	case mode.IsRegular():
		log.Println("Compiling Yara rule ", s.rulesPath)
		rulesFile, _ := os.Open(s.rulesPath)
		defer rulesFile.Close()
		err = compiler.AddString(fungeRules(s.rulesPath), "")
		if err != nil {
			log.Fatal(err)
		}
	}

	if *yaraRulesFlag != "" {
		tmpRulesFile, err := ioutil.TempFile("", "turbinia_yara")
		if err != nil {
			log.Fatalf("Unable to create temporary file: %v", err)
		}
		defer os.Remove(tmpRulesFile.Name())
		_, err = tmpRulesFile.WriteString(*yaraRulesFlag)
		if err != nil {
			log.Fatalf("Unable to write Yara rules into tmp file: %v", err)
		}
		tmpRulesFile.Sync()
		err = compiler.AddString(fungeRules(tmpRulesFile.Name()), "")
		if err != nil {
			log.Fatalf("Error adding Rule from Variable: %v", err)
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

	return nil
}

func filesystemScan(wait chan struct{}, c chan *Detection) {
	if _, err := os.Stat(*scanPathFlag); err != nil {
		log.Printf("Cannot scan: %v\n", err)
		close(c)
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
			matches, _ := scanFile(scanner, filePath, fileInfo)
			for _, match := range matches {
				var score, description, reference string
				for _, m := range match.Metas {
					if m.Identifier == "score" {
						score = strconv.Itoa(m.Value.(int))
					}
					if m.Identifier == "description" {
						description = m.Value.(string)
					}
					if m.Identifier == "reference" {
						reference = m.Value.(string)
					}
				}
				c <- newDetection(filePath, match.Rule, description, reference, score)
			}
			<-wait
			wg.Done()
		}()
		return nil
	})
	if err != nil {
		log.Printf("error walking dir: %v\n", err)
	}
	wg.Wait()
	close(c)
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
	owner, err := user.LookupId(strconv.FormatUint(uint64(stat.Uid), 10))
	if err == nil {
		ys.DefineVariable("owner", owner.Username)
	}

	ys.DefineVariable("filetype", getFileTypes(filePath))

	// Scan the file.
	err = ys.SetCallback(&matches).ScanFile(filePath)

	if err != nil {
		return matches, err
	}

	// Return any results.
	return matches, nil
}

func init() {
	scanPathFlag = flag.String("folder", "", "Specify a particular folder to be scanned")
	rulePathFlag = flag.String("rules", "", "Specify a particular path to a file or folder containing the Yara rules to use")
	magicPathFlag = flag.String("magic", "misc/file-type-signatures.txt", "A path under the rules path that contains File Magics")
	yaraRulesFlag = flag.String("yara", "", "Any additional Yara rules to be used, passed in as a string")
	flag.Parse()
}

func main() {
	if *scanPathFlag == "" || *rulePathFlag == "" {
		fmt.Println("Usage: fraken -folder <path to scan> -rules <path to rules> [-magic <path to magics>]")
		os.Exit(1)
	}
	err := scanner.init()
	if err != nil {
		fmt.Printf("Error initialising Yara engine: %v\n", err)
		os.Exit(1)
	}
	initMagics()
	waitChan := make(chan struct{}, MAX_GOROUTINES)
	resultsChan := make(chan *Detection)
	go filesystemScan(waitChan, resultsChan)
	for r := range resultsChan {
		fmt.Printf("%v,%v,%v,%v,%v,%v\n", r.ImagePath, r.SHA256, r.Signature, r.Description, r.Reference, r.Score)
	}
}
