package main

import (
	"PenBins/shared"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type CVE struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Link        string `json:"link"`
}

func (cve *CVE) ToFormattedString() string {
	return fmt.Sprintf("[ %s%s%s ]\n%s\n%s%s%s\n\n", shared.Red, cve.Name, shared.Reset, cve.Description, shared.Cyan, cve.Link, shared.Reset)
}

func cveListToJsonBytes(cveList []CVE) []byte {
	jsonBytes, err := json.MarshalIndent(cveList, "", "    ")
	if err != nil {
		return []byte{}
	}
	return jsonBytes
}

func jsonBytesToCveList(jsonBytes []byte) []CVE {
	var cveList []CVE
	err := json.Unmarshal(jsonBytes, &cveList)
	if err != nil {
		return []CVE{}
	}
	return cveList
}

func sendRequest(url string) (io.Reader, error) {
	var err error
	var resp *http.Response
	resp, err = http.Get(url)
	if err == nil {
		if 199 < resp.StatusCode && resp.StatusCode < 300 {
			// Returning the data
			return io.Reader(resp.Body), nil
		} else {
			err = fmt.Errorf("received unexpected status code: %d", resp.StatusCode)
		}
		_ = resp.Body.Close()
	}

	// An error occurred
	return nil, err
}

func extractCVEs(contentReader io.Reader) ([]CVE, error) {
	doc, err := goquery.NewDocumentFromReader(contentReader)
	if err == nil {
		var cveList []CVE
		doc.Find("#TableWithRules table tbody tr").Each(func(i int, tr *goquery.Selection) {
			tds := tr.Find("td")
			aTag := tds.Eq(0).Find("a")
			name := strings.TrimSpace(aTag.Text())
			link, _ := aTag.Attr("href")
			description := strings.TrimSpace(tds.Eq(1).Text())
			cveList = append(cveList, CVE{name, description, link})
		})
		return cveList, nil
	}
	// An error occurred if we arrived here
	return nil, err
}

func getPreviousResults(tmpPrevResultsPath string, keywords []string) []CVE {
	if len(keywords) > 1 {
		keywords = []string{strings.Join(keywords[:], "_")}
	}
	keywords[0] = strings.Replace(strings.Replace(keywords[0], "/", "_", -1), "\\", "_", -1)
	_, err := os.Stat(tmpPrevResultsPath)
	if err == nil {
		var choice string
		fmt.Print("Previous results found! Do you want to ignore them? [y/n (default)]: ")
		_, _ = fmt.Scanln(&choice)
		if len(choice) == 0 || strings.ToLower(strings.TrimSpace(choice)) != "y" {
			var jsonFile *os.File
			jsonFile, err = os.Open(tmpPrevResultsPath)
			if err == nil {
				var data []byte
				data, err = io.ReadAll(jsonFile)
				_ = jsonFile.Close()
				if err == nil {
					return jsonBytesToCveList(data)
				}
			}
		}
	}
	return []CVE{}
}

func combineCVEs(resultChan *chan []CVE, cveList *[]CVE) {
	var seenCVEs []string
	for result := range *resultChan {
		for _, currCVE := range result {
			duplicate := false
			for _, seenCVE := range *cveList {
				if seenCVE.Name == currCVE.Name {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
			seenCVEs = append(seenCVEs, currCVE.Name)
			*cveList = append(*cveList, currCVE)
		}
	}
}

func getCVEs(splitKeys bool, keywords []string, filter string, force, reverseSort bool) {
	var cveList []CVE
	if !splitKeys {
		keywords = []string{strings.Join(keywords[:], "+")}
	}
	filename := strings.Replace(strings.Replace(strings.Join(keywords[:], " "), "/", "_", -1), " ", "_", -1)
	tmpPrevResultsPath := fmt.Sprintf("%s%c%s%c%s.json", os.TempDir(), os.PathSeparator, "tmpPrevCveResults", os.PathSeparator, filename)
	if !force {
		cveList = getPreviousResults(tmpPrevResultsPath, keywords)
	}
	if len(cveList) == 0 {
		fmt.Println("Retrieving CVEs...")
		var wg sync.WaitGroup
		resultChan := make(chan []CVE, len(keywords))
		for _, key := range keywords {
			wg.Add(1)
			go func() {
				defer wg.Done()
				contentReader, err := sendRequest(fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=%s", key))
				if err == nil {
					var currCVEs []CVE
					currCVEs, err = extractCVEs(contentReader)
					if err == nil {
						resultChan <- currCVEs
					}
				}
				if err != nil {
					fmt.Println(err)
				}
			}()
		}
		wg.Wait()
		close(resultChan)
		combineCVEs(&resultChan, &cveList)
		// Ensures this is executed at the end
		defer saveResults(tmpPrevResultsPath, cveList)
	} else {
		fmt.Println("Loading CVEs...")
	}
	// Sorting the CVEs by their id
	sort.Slice(cveList, func(i, j int) bool {
		a, _ := strconv.Atoi(strings.Replace(strings.Replace(cveList[i].Name, "CVE-", "", -1), "-", "", -1))
		b, _ := strconv.Atoi(strings.Replace(strings.Replace(cveList[j].Name, "CVE-", "", -1), "-", "", -1))
		return !reverseSort && a < b || reverseSort && a > b
	})
	formattedCVEs := getFormattedCVEs(cveList, filter)
	fmt.Print(formattedCVEs)
}

func saveResults(tmpPrevResultsPath string, cveList []CVE) {
	_ = os.MkdirAll(filepath.Dir(tmpPrevResultsPath), 0755)
	jsonFile, err := os.OpenFile(tmpPrevResultsPath, os.O_RDWR|os.O_CREATE, 0644)
	if err == nil {
		_, err = jsonFile.Write(cveListToJsonBytes(cveList))
		if err == nil {
			fmt.Printf("%sResults saved at '%s%s'\n", shared.Yellow, tmpPrevResultsPath, shared.Reset)
		}
		_ = jsonFile.Close()
	}
}

func getFormattedCVEs(cveList []CVE, filter string) string {
	var cveString string
	lowercaseFilter := strings.ToLower(filter)
	var lowercaseWordFilter string
	if strings.Index(lowercaseFilter, ".") > 0 {
		lowercaseWordFilter = lowercaseFilter
	} else {
		lowercaseWordFilter = fmt.Sprintf(" %s ", lowercaseFilter)
	}
	for _, cve := range cveList {
		if filter == "" || strings.Contains(strings.ToLower(cve.Name), lowercaseFilter) || strings.Contains(strings.ToLower(cve.Description), lowercaseWordFilter) {
			cveString += cve.ToFormattedString()
		}
	}
	return cveString
}

func parseParameters(splitKeys *bool, filter *string, keywords *[]string, force *bool, reverseSort *bool) {
	flag.BoolVar(splitKeys, "s", false, "splits keys into multiple queries")
	flag.StringVar(filter, "f", "", "used to filter results")
	flag.BoolVar(force, "force", false, "forces a new fetch and ignores pre-existent results")
	flag.BoolVar(reverseSort, "r", false, "reverse CVEs sorting")
	flag.Usage = func() {
		fmt.Println("Usage: cve [OPTIONS] k1 k2 k3...")
		flag.PrintDefaults()
		os.Exit(1)
	}
	flag.Parse()
	*keywords = flag.Args()
	if len(os.Args) < 2 || len(*keywords) == 0 {
		flag.Usage()
	}

	for _, keyword := range *keywords {
		if string(keyword[0]) == "-" {
			flag.Usage()
		}
	}
}

func main() {
	var splitKeys bool
	var filter string
	var keywords []string
	var force bool
	var reverseSort bool
	parseParameters(&splitKeys, &filter, &keywords, &force, &reverseSort)
	getCVEs(splitKeys, keywords, filter, force, reverseSort)
}
