# Domain Email Audit

Shell script that checks the email security policies for domains by verifying their SPF, DKIM, and DMARC records. It provides a detailed report on the configuration of these records to ensure proper email authentication, security, and compliance with common email standards.

## Features

- Checks SPF, DKIM, and DMARC records for specified domains.
- Supports input from a list of domains provided via a file or comma-separated values.
- Verifies that each record is configured correctly and complies with standard email authentication practices.
- DKIM records discovery by brute-forcing using a provided wordlist of selectors.
- Optionally generates a CSV report containing the audit results for each domain.

## Prerequisites

- Unix-like, Linux or macOS environment (works on systems with bash and dig installed).
- The script uses dig to query DNS records, so you need to have it installed and accessible from the terminal.

  You can install dig using:

  ```
  sudo apt-get install dnsutils  # On Debian-based systems
  sudo yum install bind-utils # On RHEL-based systems 
  brew install bind  # On macOS (using Homebrew)
  ```

## Installation

Clone this repository or download the domain_email_audit.sh script.

   ```
   git clone https://github.com/your-username/domain_email_audit.git && cd domain_email_audit && chmod +x domain_email_audit.sh
   ```

## Usage

### Comma-separated domain list

To check a set of domains, use the -d flag to specify the domains as a comma-separated list.

```
./domain_email_audit.sh -d domain1.com,domain2.com
```

### Domain file list

You can also provide a file containing a list of domains using the -f flag:

```
./domain_email_audit.sh -f domains.txt
```

Where domains.txt contains one domain per line.

### Selectors for DKIM Check (recommended)

If you want to discover or check DKIM records, provide a file with selectors using the -w flag:

```
./domain_email_audit.sh -f domains.txt -w selectors.txt
```

Where selectors.txt contains one selector per line.

### Report Generation

To generate a CSV report of the audit results, use the --report flag. The script will generate a CSV file with the audit results and save it with the script name and timestamp.

```
./domain_email_audit.sh -f domains.txt -w selectors.txt --report
```

The CSV file will be named like domain_email_audit.sh.YYYY-MM-DD_HH-MM-SS.csv.

### Full Example

```
./domain_email_audit.sh -f domains.txt -w selectors.txt --report
```

This command checks SPF, DKIM, and DMARC records for domain1.com and domain2.com, uses selectors from selectors.txt for DKIM, and generates a CSV report.

## Output

The script will print a detailed report in the terminal showing the status of DMARC, SPF, and DKIM records for each domain. The output will include:

- DMARC status (ok or nok with a reason if nok)
- SPF status (ok or nok with a reason if nok)
- DKIM status (ok or nok with the selectors that passed)

### Example Output

```
DOMAIN                    DMARC    SPF      DKIM     DMARC POLICY     SPF FAILURE REASON             DKIM SELECTORS                          
domain1.com               ok       ok       ok       reject           -                              20161025 delta                          
domain2.com               ok       nok      ok       reject           exceeds 512 bytes              mail s1 s2 selector1 selector2          
domain3.com               ok       nok      ok       reject           exceeds 10 DNS lookups         k2 k3 s1 s2 selector1 selector2         
domain4.com     	  nok      ok       nok      no DMARC record  -                              -                                       
domain5.com      	  nok      ok       ok       no DMARC record  -                              selector1 selector2  
```

### Example CSV Output

The CSV report will have the following columns:

- DOMAIN: The domain being checked.
- DMARC: Status of the DMARC record (ok or nok).
- SPF: Status of the SPF record (ok or nok).
- DKIM: Status of the DKIM record (ok or nok).
- DMARC_POLICY: The DMARC policy (none, quarantine, or reject).
- SPF_FAILURE_REASON: The reason for SPF failure (if any).
- DKIM_SELECTORS: List of DKIM selectors that passed (if any).

### Example CSV:

```
DOMAIN;DMARC;SPF;DKIM;DMARC_POLICY;SPF_FAILURE_REASON;DKIM_SELECTORS
domain1.com;ok;ok;ok;reject;-;20161025 delta
domain2.com;ok;nok;ok;reject;exceeds 512 bytes;mail s1 s2 selector1 selector2
domain3.com;ok;nok;ok;reject;exceeds 10 DNS lookups;k2 k3 s1 s2 selector1 selector2
domain4.com;nok;ok;nok;no DMARC record;-;-
domain5.com;nok;ok;ok;no DMARC record;-;selector1 selector2
```

## Options

- -d <domains>: Comma-separated list of domains to check (e.g., domain1.com,domain2.com).
- -f <file>: File containing a list of domains (one domain per line).
- -w <file>: File containing a list of DKIM selectors to check (one selector per line).
- --report: Generate a CSV report with audit results.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
