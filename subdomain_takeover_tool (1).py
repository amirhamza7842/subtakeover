#!/usr/bin/env python3
"""
Advanced Subdomain Takeover Detection Tool
High-accuracy subdomain takeover scanner with comprehensive reporting
"""

import asyncio
import aiohttp
import dns.resolver
import dns.exception
import argparse
import json
import sys
import time
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Set
from urllib.parse import urlparse
import re
from dataclasses import dataclass
from enum import Enum
import ssl
import socket
import subprocess
import platform

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

class VulnStatus(Enum):
    VULNERABLE = "VULNERABLE"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    POSSIBLE = "POSSIBLE"
    UNKNOWN = "UNKNOWN"

@dataclass
class SubdomainResult:
    subdomain: str
    cnames: List[str]
    status: VulnStatus
    service: str
    error_signatures: List[str]
    http_status: Optional[int]
    response_body: str
    fingerprints: List[str]
    poc_details: Dict[str, str]
    confidence: float
    timestamp: str

class ServiceFingerprints:
    """Advanced fingerprinting database for various cloud services"""
    
    FINGERPRINTS = {
        'github': {
            'cname_patterns': [r'.*\.github\.io$', r'.*\.githubusercontent\.com$'],
            'error_signatures': [
                'There isn\'t a GitHub Pages site here.',
                'For root URLs (like http://example.com/) you must provide an index.html file',
                '404 - File not found'
            ],
            'status_codes': [404],
            'headers': {'server': 'GitHub.com'},
            'vulnerability_indicators': ['There isn\'t a GitHub Pages site here.'],
            'severity': 'HIGH'
        },
        'heroku': {
            'cname_patterns': [r'.*\.herokuapp\.com$', r'.*\.herokudns\.com$'],
            'error_signatures': [
                'No such app',
                'heroku | no such app',
                'Application Error'
            ],
            'status_codes': [404, 503],
            'headers': {'server': 'Cowboy'},
            'vulnerability_indicators': ['No such app', 'heroku | no such app'],
            'severity': 'HIGH'
        },
        'amazon_s3': {
            'cname_patterns': [r'.*\.s3\.amazonaws\.com$', r'.*\.s3-.*\.amazonaws\.com$'],
            'error_signatures': [
                'NoSuchBucket',
                'The specified bucket does not exist',
                'BucketNotFound'
            ],
            'status_codes': [404],
            'headers': {'server': 'AmazonS3'},
            'vulnerability_indicators': ['NoSuchBucket', 'The specified bucket does not exist'],
            'severity': 'CRITICAL'
        },
        'cloudfront': {
            'cname_patterns': [r'.*\.cloudfront\.net$'],
            'error_signatures': [
                'Bad Request',
                'The request could not be satisfied',
                'ERROR: The request could not be satisfied'
            ],
            'status_codes': [403, 404],
            'headers': {'server': 'CloudFront'},
            'vulnerability_indicators': ['Bad Request', 'The request could not be satisfied'],
            'severity': 'HIGH'
        },
        'azure': {
            'cname_patterns': [r'.*\.azurewebsites\.net$', r'.*\.azure\.com$', r'.*\.cloudapp\.net$'],
            'error_signatures': [
                'Web App - Unavailable',
                'Error 404 - Web app not found',
                'This web app has been stopped'
            ],
            'status_codes': [404],
            'headers': {},
            'vulnerability_indicators': ['Web App - Unavailable', 'Error 404 - Web app not found'],
            'severity': 'HIGH'
        },
        'netlify': {
            'cname_patterns': [r'.*\.netlify\.app$', r'.*\.netlify\.com$'],
            'error_signatures': [
                'Not Found - Request ID',
                'Page Not Found',
                'Looks like you\'ve followed a broken link'
            ],
            'status_codes': [404],
            'headers': {'server': 'Netlify'},
            'vulnerability_indicators': ['Not Found - Request ID'],
            'severity': 'MEDIUM'
        },
        'vercel': {
            'cname_patterns': [r'.*\.vercel\.app$', r'.*\.now\.sh$'],
            'error_signatures': [
                'The deployment could not be found',
                'DEPLOYMENT_NOT_FOUND',
                'This Serverless Function has crashed'
            ],
            'status_codes': [404],
            'headers': {'server': 'Vercel'},
            'vulnerability_indicators': ['DEPLOYMENT_NOT_FOUND'],
            'severity': 'MEDIUM'
        },
        'fastly': {
            'cname_patterns': [r'.*\.fastly\.com$', r'.*\.fastlylb\.net$'],
            'error_signatures': [
                'Fastly error: unknown domain',
                'Request unsuccessful'
            ],
            'status_codes': [404],
            'headers': {'server': 'Fastly'},
            'vulnerability_indicators': ['Fastly error: unknown domain'],
            'severity': 'HIGH'
        }
    }

class SubdomainTakeoverScanner:
    def __init__(self, timeout: int = 15, max_concurrent: int = 20):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.session = None
        self.results: List[SubdomainResult] = []
        
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent,
            limit_per_host=5,
            ssl=False,
            ttl_dns_cache=300,
            use_dns_cache=True
        )
        
        timeout = aiohttp.ClientTimeout(total=self.timeout, connect=8)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'SubTakeover-Scanner/2.0'}
        )
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def print_banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║              Advanced Subdomain Takeover Scanner                 ║
║                    High-Precision Detection                      ║
║                         v2.1 Enhanced                           ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.YELLOW}[INFO]{Colors.RESET} Initializing DNS resolvers and HTTP clients...
        """
        print(banner)

    async def resolve_cnames(self, domain: str) -> List[str]:
        """Resolve CNAME records with comprehensive chain following using dnspython"""
        cnames = []
        current_domain = domain
        seen_domains = set()
        
        try:
            # Create DNS resolver with proper settings
            resolver = dns.resolver.Resolver()
            resolver.timeout = 8
            resolver.lifetime = 10
            
            while current_domain and current_domain not in seen_domains:
                seen_domains.add(current_domain)
                
                try:
                    # Add delay to prevent overwhelming DNS servers
                    await asyncio.sleep(0.1)
                    
                    # Resolve CNAME in thread pool to avoid blocking
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(
                        None, 
                        lambda: resolver.resolve(current_domain, 'CNAME')
                    )
                    
                    if result:
                        cname = str(result[0]).rstrip('.')
                        cnames.append(cname)
                        current_domain = cname
                        print(f"{Colors.CYAN}[DNS]{Colors.RESET} {domain} -> {cname}")
                    else:
                        break
                        
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    # No CNAME record found, this is normal
                    break
                except dns.exception.Timeout:
                    print(f"{Colors.YELLOW}[WARN]{Colors.RESET} DNS timeout for {current_domain}")
                    break
                except Exception as e:
                    print(f"{Colors.YELLOW}[WARN]{Colors.RESET} DNS error for {current_domain}: {str(e)}")
                    break
                    
                # Prevent infinite loops
                if len(cnames) > 15:
                    break
                    
        except Exception as e:
            print(f"{Colors.YELLOW}[WARN]{Colors.RESET} DNS resolution failed for {domain}: {str(e)}")
            
        return cnames

    def identify_service(self, cnames: List[str]) -> str:
        """Identify cloud service from CNAME patterns"""
        for service, config in ServiceFingerprints.FINGERPRINTS.items():
            for cname in cnames:
                for pattern in config['cname_patterns']:
                    if re.match(pattern, cname, re.IGNORECASE):
                        return service
        return "unknown"

    async def check_http_response(self, domain: str) -> Tuple[Optional[int], str, Dict[str, str]]:
        """Check HTTP response with proper error handling and delays"""
        headers = {}
        status_code = None
        response_body = ""
        
        # Add delay to prevent overwhelming servers
        await asyncio.sleep(0.2)
        
        for scheme in ['https', 'http']:
            try:
                url = f"{scheme}://{domain}"
                print(f"{Colors.BLUE}[HTTP]{Colors.RESET} Testing {url}")
                
                async with self.session.get(
                    url, 
                    allow_redirects=True, 
                    ssl=False,
                    max_redirects=3
                ) as response:
                    status_code = response.status
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    
                    # Read response body with size limit
                    try:
                        response_body = await response.text(encoding='utf-8', errors='ignore')
                        if len(response_body) > 5000:
                            response_body = response_body[:5000]
                    except:
                        response_body = ""
                    
                    break
                    
            except asyncio.TimeoutError:
                print(f"{Colors.YELLOW}[WARN]{Colors.RESET} HTTP timeout for {scheme}://{domain}")
                continue
            except Exception as e:
                print(f"{Colors.YELLOW}[WARN]{Colors.RESET} HTTP error for {scheme}://{domain}: {str(e)}")
                continue
                
        return status_code, response_body, headers

    def analyze_vulnerability(self, service: str, status_code: Optional[int], 
                           response_body: str, headers: Dict[str, str], 
                           cnames: List[str]) -> Tuple[VulnStatus, List[str], float, Dict[str, str]]:
        """Advanced vulnerability analysis with confidence scoring"""
        
        if service == "unknown":
            return VulnStatus.UNKNOWN, [], 0.0, {}
            
        config = ServiceFingerprints.FINGERPRINTS.get(service, {})
        error_signatures = []
        confidence = 0.0
        poc_details = {}
        
        # Check error signatures in response body
        vulnerability_found = False
        for signature in config.get('vulnerability_indicators', []):
            if signature.lower() in response_body.lower():
                error_signatures.append(signature)
                vulnerability_found = True
                confidence += 0.4
                
        # Check status codes
        if status_code in config.get('status_codes', []):
            confidence += 0.3
            
        # Check headers
        for header, expected_value in config.get('headers', {}).items():
            if header.lower() in [h.lower() for h in headers.keys()]:
                if expected_value.lower() in headers.get(header, '').lower():
                    confidence += 0.2
                    
        # Additional checks for specific services
        if service == 'github' and vulnerability_found:
            poc_details['exploit_steps'] = "1. Create GitHub Pages repo\n2. Configure custom domain\n3. Takeover complete"
            poc_details['impact'] = "Full subdomain control, potential phishing/malware hosting"
            
        elif service == 'amazon_s3' and vulnerability_found:
            poc_details['exploit_steps'] = "1. Create S3 bucket with exact name\n2. Configure static website hosting\n3. Upload content"
            poc_details['impact'] = "Critical - Full control over subdomain content"
            
        elif service == 'heroku' and vulnerability_found:
            poc_details['exploit_steps'] = "1. Create Heroku app with matching name\n2. Deploy application\n3. Configure custom domain"
            poc_details['impact'] = "High - Application hosting under target domain"
            
        # Determine final status
        if vulnerability_found and confidence >= 0.7:
            return VulnStatus.VULNERABLE, error_signatures, confidence, poc_details
        elif vulnerability_found and confidence >= 0.4:
            return VulnStatus.POSSIBLE, error_signatures, confidence, poc_details
        elif confidence > 0.2:
            return VulnStatus.NOT_VULNERABLE, error_signatures, confidence, {}
        else:
            return VulnStatus.UNKNOWN, error_signatures, confidence, {}

    async def scan_subdomain(self, domain: str) -> SubdomainResult:
        """Comprehensive subdomain analysis with proper pacing"""
        print(f"\n{Colors.BOLD}[SCAN]{Colors.RESET} Starting analysis: {Colors.CYAN}{domain}{Colors.RESET}")
        
        # Resolve CNAME chain with delay
        cnames = await self.resolve_cnames(domain)
        
        if not cnames:
            print(f"{Colors.YELLOW}[INFO]{Colors.RESET} No CNAME records found for {domain}")
            return SubdomainResult(
                subdomain=domain,
                cnames=[],
                status=VulnStatus.NOT_VULNERABLE,
                service="none",
                error_signatures=[],
                http_status=None,
                response_body="",
                fingerprints=[],
                poc_details={},
                confidence=0.0,
                timestamp=datetime.now().isoformat()
            )
        
        print(f"{Colors.GREEN}[DNS]{Colors.RESET} Found {len(cnames)} CNAME record(s)")
        
        # Identify service
        service = self.identify_service(cnames)
        print(f"{Colors.BLUE}[SERVICE]{Colors.RESET} Identified service: {Colors.MAGENTA}{service.upper()}{Colors.RESET}")
        
        # Check HTTP response
        status_code, response_body, headers = await self.check_http_response(domain)
        
        if status_code:
            print(f"{Colors.GREEN}[HTTP]{Colors.RESET} Response: {status_code}")
        
        # Analyze vulnerability
        vuln_status, error_sigs, confidence, poc_details = self.analyze_vulnerability(
            service, status_code, response_body, headers, cnames
        )
        
        # Add processing delay to ensure proper analysis
        await asyncio.sleep(0.5)
        
        return SubdomainResult(
            subdomain=domain,
            cnames=cnames,
            status=vuln_status,
            service=service,
            error_signatures=error_sigs,
            http_status=status_code,
            response_body=response_body[:500],  # Truncate for storage
            fingerprints=[service] if service != "unknown" else [],
            poc_details=poc_details,
            confidence=confidence,
            timestamp=datetime.now().isoformat()
        )

    def print_result(self, result: SubdomainResult):
        """Print formatted result with colors"""
        status_colors = {
            VulnStatus.VULNERABLE: Colors.RED,
            VulnStatus.POSSIBLE: Colors.YELLOW,
            VulnStatus.NOT_VULNERABLE: Colors.GREEN,
            VulnStatus.UNKNOWN: Colors.BLUE
        }
        
        color = status_colors.get(result.status, Colors.WHITE)
        
        print(f"\n{Colors.BOLD}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}Subdomain:{Colors.RESET} {result.subdomain}")
        print(f"{Colors.BOLD}Status:{Colors.RESET} {color}{result.status.value}{Colors.RESET}")
        print(f"{Colors.BOLD}Service:{Colors.RESET} {result.service.upper()}")
        print(f"{Colors.BOLD}Confidence:{Colors.RESET} {result.confidence:.2%}")
        
        if result.cnames:
            print(f"{Colors.BOLD}CNAME Chain:{Colors.RESET}")
            for i, cname in enumerate(result.cnames, 1):
                print(f"  {i}. {cname}")
        
        if result.http_status:
            print(f"{Colors.BOLD}HTTP Status:{Colors.RESET} {result.http_status}")
            
        if result.error_signatures:
            print(f"{Colors.BOLD}Error Signatures:{Colors.RESET}")
            for sig in result.error_signatures:
                print(f"  • {Colors.RED}{sig}{Colors.RESET}")
                
        if result.poc_details:
            print(f"{Colors.BOLD}PoC Details:{Colors.RESET}")
            for key, value in result.poc_details.items():
                print(f"  {Colors.CYAN}{key.title()}:{Colors.RESET} {value}")

    def export_results(self, filename: str):
        """Export results to JSON"""
        export_data = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'total_subdomains': len(self.results),
                'vulnerable_count': len([r for r in self.results if r.status == VulnStatus.VULNERABLE]),
                'possible_count': len([r for r in self.results if r.status == VulnStatus.POSSIBLE])
            },
            'results': []
        }
        
        for result in self.results:
            export_data['results'].append({
                'subdomain': result.subdomain,
                'cnames': result.cnames,
                'status': result.status.value,
                'service': result.service,
                'error_signatures': result.error_signatures,
                'http_status': result.http_status,
                'confidence': result.confidence,
                'poc_details': result.poc_details,
                'timestamp': result.timestamp
            })
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"\n{Colors.GREEN}[SUCCESS]{Colors.RESET} Results exported to {filename}")

    async def scan_domains(self, domains: List[str]):
        """Scan multiple domains with controlled concurrency"""
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def scan_with_semaphore(domain):
            async with semaphore:
                return await self.scan_subdomain(domain.strip())
        
        print(f"{Colors.CYAN}[INFO]{Colors.RESET} Starting scan of {len(domains)} domain(s) with max {self.max_concurrent} concurrent connections")
        
        tasks = [scan_with_semaphore(domain) for domain in domains if domain.strip()]
        self.results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and convert to proper results
        valid_results = []
        for i, result in enumerate(self.results):
            if isinstance(result, Exception):
                print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to scan {domains[i]}: {str(result)}")
            else:
                valid_results.append(result)
        
        self.results = valid_results
        
        # Print results
        vulnerable_count = 0
        possible_count = 0
        
        for result in self.results:
            self.print_result(result)
            if result.status == VulnStatus.VULNERABLE:
                vulnerable_count += 1
            elif result.status == VulnStatus.POSSIBLE:
                possible_count += 1
        
        # Summary
        print(f"\n{Colors.BOLD}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}SCAN SUMMARY{Colors.RESET}")
        print(f"Total Subdomains: {len(self.results)}")
        print(f"{Colors.RED}Vulnerable: {vulnerable_count}{Colors.RESET}")
        print(f"{Colors.YELLOW}Possible: {possible_count}{Colors.RESET}")
        print(f"{Colors.GREEN}Safe: {len(self.results) - vulnerable_count - possible_count}{Colors.RESET}")

def check_dependencies():
    """Check if required dependencies are installed"""
    required_packages = ['aiohttp', 'dnspython']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"{Colors.RED}[ERROR]{Colors.RESET} Missing required packages: {', '.join(missing_packages)}")
        print(f"{Colors.YELLOW}[INFO]{Colors.RESET} Install with: pip install {' '.join(missing_packages)}")
        return False
    return True

def install_tool():
    """Instructions for installing the tool globally"""
    print(f"""
{Colors.CYAN}{Colors.BOLD}INSTALLATION INSTRUCTIONS{Colors.RESET}

{Colors.YELLOW}1. Save this script as 'subtakeover.py'{Colors.RESET}

{Colors.YELLOW}2. Install dependencies:{Colors.RESET}
   pip install aiohttp dnspython

{Colors.YELLOW}3. Make executable (Linux/Mac):{Colors.RESET}
   chmod +x subtakeover.py

{Colors.YELLOW}4. Install globally (Optional):{Colors.RESET}
   
   {Colors.BOLD}Linux/Mac:{Colors.RESET}
   sudo cp subtakeover.py /usr/local/bin/subtakeover
   sudo chmod +x /usr/local/bin/subtakeover
   
   {Colors.BOLD}Or add to PATH:{Colors.RESET}
   echo 'export PATH=$PATH:/path/to/your/script' >> ~/.bashrc
   source ~/.bashrc

{Colors.YELLOW}5. Usage from anywhere:{Colors.RESET}
   subtakeover -d example.com
   subtakeover -l domains.txt -o results.json

{Colors.YELLOW}6. Docker Installation:{Colors.RESET}
   docker build -t subtakeover .
   docker run -v $(pwd):/data subtakeover -l /data/domains.txt
    """)

async def main():
    if not check_dependencies():
        sys.exit(1)
        
    parser = argparse.ArgumentParser(description='Advanced Subdomain Takeover Scanner')
    parser.add_argument('-d', '--domain', help='Single domain to scan')
    parser.add_argument('-l', '--list', help='File containing list of domains')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('-t', '--timeout', type=int, default=15, help='Request timeout (default: 15)')
    parser.add_argument('-c', '--concurrent', type=int, default=10, help='Max concurrent requests (default: 10)')
    parser.add_argument('--install', action='store_true', help='Show installation instructions')
    
    args = parser.parse_args()
    
    if args.install:
        install_tool()
        return
    
    if not args.domain and not args.list:
        parser.error("Either --domain or --list must be specified. Use --install for setup instructions.")
    
    domains = []
    if args.domain:
        domains = [args.domain]
    elif args.list:
        try:
            with open(args.list, 'r') as f:
                domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} File not found: {args.list}")
            sys.exit(1)
    
    if args.concurrent > 20:
        print(f"{Colors.YELLOW}[WARN]{Colors.RESET} High concurrency ({args.concurrent}) may cause rate limiting. Recommended: 5-15")
    
    async with SubdomainTakeoverScanner(timeout=args.timeout, max_concurrent=args.concurrent) as scanner:
        scanner.print_banner()
        
        start_time = time.time()
        await scanner.scan_domains(domains)
        end_time = time.time()
        
        print(f"\n{Colors.CYAN}[INFO]{Colors.RESET} Scan completed in {end_time - start_time:.2f} seconds")
        
        if args.output:
            scanner.export_results(args.output)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[INFO]{Colors.RESET} Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.RESET} {str(e)}")
        sys.exit(1)