# DeepThought Company Intelligence Scraper

A production-grade web scraper for extracting structured company information from business websites. Built for pharma intelligence firm DeepThought, this scraper converts a company website URL into a clean, structured, decision-usable Company Info Record.

## 🧪 Real-World Testing

This scraper has been tested and validated with real-world company websites:

- **AB-BIOTICS** (`https://www.ab-biotics.com/`) - Global probiotic manufacturer
- **SiteW** (`https://www.en.sitew.com/`) - Website creation platform

**Demo Outputs**: Complete scraping results are available in the repository:
- `ab_biotics_output.json` - Full extraction from AB-BIOTICS (pharmaceutical/probiotics industry)
- `sitew_output.json` - Full extraction from SiteW (web services industry)

These real-world examples demonstrate the scraper's ability to extract:
- International contact information (phone numbers, addresses)
- Multiple therapeutic areas and target industries
- Social media links with validation
- Partner testimonials and proof signals
- Team structure and departments

## Overview

This scraper is designed with the following principles:
- **Truthful**: Never hallucinates or guesses missing data
- **Explicit**: Distinguishes between scraped, inferred, and not found data
- **Robust**: Handles errors gracefully and logs limitations clearly
- **Deterministic**: Consistent, repeatable output structure
- **Login-Aware**: Automatically detects and handles login-protected sites

The scraper intelligently crawls a company website (up to 15 pages, depth 5) and extracts structured information across six key categories:
1. **Identity**: Company name, website URL, tagline
2. **Business Summary**: What they do, primary offerings, target customers
3. **Evidence/Proof Signals**: Key pages detected, proof signals (clients, case studies, testimonials, certifications), social links
4. **Contact & Location**: Emails, phone numbers, physical address, contact page
5. **Team & Hiring Signals**: Careers page, roles/departments mentioned
6. **Metadata**: Timestamp, pages visited, crawl depth, errors/limitations, login status

## Features

### Core Functionality
- **Smart Crawling**: Prioritizes important pages (about, products, solutions, contact, careers, etc.)
- **Comprehensive Extraction**: Extracts company name, tagline, offerings, contact info, social links, and more
- **Proof Signal Detection**: Identifies evidence of clients, case studies, testimonials, and certifications
- **Error Handling**: Gracefully handles timeouts, broken links, redirects, and JS-heavy sites
- **Robots.txt Compliance**: Respects robots.txt rules (with logging)
- **Structured Output**: Consistent JSON format with all keys always present

### Advanced Features
- **Login Detection**: Automatically detects login-protected sites and returns appropriate message without scraping
- **Footer Extraction**: Prioritizes footer content for contact information (emails, phones, addresses)
- **International Support**: Handles phone numbers and addresses from various countries (US, India, Europe, UK, etc.)
- **Enhanced Company Name Extraction**: Multiple strategies including logo alt text, structured data, meta tags
- **Smart Tagline Detection**: Hero sections, meta descriptions, and multiple CSS selector strategies
- **Social Link Validation**: Exact domain matching to reduce false positives
- **Promotional Content Filtering**: Automatically filters out e-commerce noise and promotional banners
- **Target Industry Extraction**: Enhanced detection of target customers and industries

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Setup

1. Clone or download this repository
2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Scrape a company website and print results to stdout:

```bash
python scraper.py https://example.com
```

### Save to File

Save results to a JSON file:

```bash
python scraper.py https://example.com -o output.json
```

### Real-World Examples

Test with real company websites (examples included in repository):

```bash
# Example 1: AB-BIOTICS (Pharmaceutical/Probiotics company)
python scraper.py https://www.ab-biotics.com/ -o ab_biotics_output.json

# Example 2: Any other company website
python scraper.py https://company-website.com/ -o output.json
```

**Demo Outputs**: This repository includes real-world scraping results:
- `ab_biotics_output.json` - Complete extraction from AB-BIOTICS website
- `sitew_output.json` - Additional real-world test case

### Verbose Logging

Enable detailed logging for debugging:

```bash
python scraper.py https://example.com -v
```

### Command Line Options

```
positional arguments:
  url                   Company website URL to scrape

optional arguments:
  -h, --help            Show help message
  -o OUTPUT, --output OUTPUT
                        Output JSON file path (default: print to stdout)
  -v, --verbose         Enable verbose logging
```

## Dependencies

- **requests** (>=2.31.0): HTTP library for fetching web pages
- **beautifulsoup4** (>=4.12.0): HTML parsing library
- **lxml** (>=4.9.0): Fast XML/HTML parser (used by BeautifulSoup)

## Real-World Test Cases

### Test Case 1: AB-BIOTICS (Pharmaceutical/Probiotics)
**URL**: `https://www.ab-biotics.com/`

A global probiotic manufacturer based in Spain. This test demonstrates:
- International phone number extraction (Spanish format: `(+34) 93 849 63 44`)
- Multiple physical addresses (Europe, North America, APAC)
- Therapeutic area detection (10 areas extracted)
- Partner testimonials extraction
- Social media link validation (LinkedIn, YouTube)
- Department structure extraction

**Output File**: `ab_biotics_output.json`

### Test Case 2: SiteW (Web Services)
**URL**: `https://www.en.sitew.com/`

A website creation platform. This test demonstrates:
- Company name extraction from various sources
- Service offerings extraction
- Contact information extraction
- Business model identification

**Output File**: `sitew_output.json`

## Example Output

The following examples are based on real-world scraping results. Full output files are available in the repository directory.

### Successful Scrape Example (AB-BIOTICS)

```json
{
  "identity": {
    "company_name": "AB",
    "website_url": "https://www.ab-biotics.com/",
    "tagline": "Bringing probiotics to life"
  },
  "business_summary": {
    "what_they_do": "We are pioneers in probiotic excellence AB-BIOTICS is a leading player in the probiotic space that makes advanced probiotic science a reality...",
    "primary_offerings": [
      "Probiotic strains",
      "Probiotic formulas",
      "Market-ready probiotic products"
    ],
    "target_customers_or_industries": [
      "Gastrointestinal health",
      "Pediatric health",
      "Oral health",
      "Eye health",
      "Immune health",
      "Cardiometabolic health",
      "Skin health",
      "Women's health",
      "Cognitive health",
      "Healthy Ageing"
    ]
  },
  "evidence_proof_signals": {
    "key_pages_detected": [
      "solutions",
      "about",
      "careers",
      "industries"
    ],
    "proof_signals_found": {
      "clients": false,
      "case_studies": false,
      "testimonials": true,
      "certifications_awards": true
    },
    "social_links": {
      "linkedin": "https://www.linkedin.com/company/ab-biotics/",
      "youtube": "https://www.youtube.com/watch?v=uxqrbMCsy7o"
    }
  },
  "contact_location": {
    "emails": [],
    "phone_numbers": [
      "(+34) 93 849 63 44"
    ],
    "physical_address": "Av. Can Fatjó dels Aurons, 3, CUB 1, 08174 Sant Cugat del Vallès, Barcelona, Spain",
    "contact_page_url": "https://www.ab-biotics.com/get-in-touch/"
  },
  "team_hiring_signals": {
    "careers_page_url": "https://www.ab-biotics.com/team/",
    "roles_or_departments_mentioned": [
      "Research & Development",
      "Business Development",
      "Regulatory & Quality",
      "Marketing",
      "Manufacturing"
    ]
  },
  "metadata": {
    "timestamp_of_scrape": "2025-12-24T12:00:15.007159Z",
    "pages_visited": [
      "https://www.ab-biotics.com/",
      "https://www.ab-biotics.com/solutions/",
      "https://www.ab-biotics.com/about-us/",
      "https://www.ab-biotics.com/team/"
    ],
    "crawl_depth_used": 5,
    "errors_or_limitations": [],
    "login_required": false
  }
}
```

**Note**: Full detailed outputs from real-world tests are available in the repository:
- `ab_biotics_output.json` - Complete output from AB-BIOTICS scraping
- `sitew_output.json` - Complete output from additional real-world test

### Login-Protected Site

When a site requires login, the scraper returns a minimal structure:

```json
{
  "identity": {
    "company_name": null,
    "website_url": "https://example.com",
    "tagline": null
  },
  "business_summary": {
    "what_they_do": null,
    "primary_offerings": [],
    "target_customers_or_industries": []
  },
  "evidence_proof_signals": {
    "key_pages_detected": [],
    "proof_signals_found": {
      "clients": false,
      "case_studies": false,
      "testimonials": false,
      "certifications_awards": false
    },
    "social_links": {}
  },
  "contact_location": {
    "emails": [],
    "phone_numbers": [],
    "physical_address": null,
    "contact_page_url": null
  },
  "team_hiring_signals": {
    "careers_page_url": null,
    "roles_or_departments_mentioned": []
  },
  "metadata": {
    "timestamp_of_scrape": "2024-01-15T10:30:00.000000Z",
    "pages_visited": [],
    "crawl_depth_used": 0,
    "errors_or_limitations": [
      "LOGIN_REQUIRED: This website requires login/authentication to access information. Only publicly accessible content can be scraped."
    ],
    "login_required": true
  }
}
```

## How It Works

1. **URL Normalization**: The scraper normalizes the input URL and validates it
2. **Login Detection**: Checks if the site requires login/authentication before scraping
3. **Homepage Analysis**: Starts by analyzing the homepage for company identity and basic information
4. **Priority Crawling**: Crawls priority pages (about, products, solutions, contact, careers, etc.) first
5. **Content Extraction**: Extracts structured information using multiple strategies:
   - HTML structure analysis (headings, sections, lists)
   - Meta tags and structured data (JSON-LD)
   - Pattern matching (emails, phone numbers, addresses)
   - Text analysis for proof signals
   - Footer-specific extraction for contact information
6. **Data Aggregation**: Combines information from all visited pages
7. **Output Generation**: Produces a consistent JSON structure with all required fields

## Configuration

The scraper has the following configurable parameters (in `CompanyScraper` class):

- `MAX_PAGES`: Maximum number of pages to crawl (default: 15)
- `MAX_DEPTH`: Maximum crawl depth (default: 5)
- `TIMEOUT`: Request timeout in seconds (default: 10)
- `PRIORITY_PATHS`: List of priority URL paths to crawl first
- `SOCIAL_DOMAINS`: Dictionary of social media platforms and their domains
- `PROMOTIONAL_PATTERNS`: Regex patterns to filter promotional content

## Login Detection

The scraper automatically detects login-protected sites through multiple methods:

1. **URL Analysis**: Checks for login-related paths (`/login`, `/signin`, `/auth`, etc.)
2. **Page Title**: Analyzes page title for login keywords
3. **Form Detection**: Identifies prominent login forms with password fields
4. **Text Patterns**: Searches for login-related text ("please log in", "access denied", etc.)
5. **Redirect Detection**: Checks for redirects to login pages
6. **HTTP Headers**: Detects HTTP authentication requirements

When login is detected:
- Scraping stops immediately
- Returns minimal JSON structure
- Sets `login_required: true` in metadata
- Includes clear error message in `errors_or_limitations`

## Extraction Strategies

### Company Name
1. Logo alt text or title attribute
2. Structured data (JSON-LD)
3. Meta tags (og:site_name)
4. Title tag (with intelligent cleaning)
5. First H1 tag
6. Domain name (fallback)

### Tagline
1. Hero section tagline
2. Meta description
3. First H2 after H1
4. Common CSS selectors (.tagline, .subtitle, .lead)

### Contact Information
1. **Footer Priority**: Extracts from footer first (most reliable)
2. **Mailto/Tel Links**: Extracts from `mailto:` and `tel:` links
3. **Pattern Matching**: Regex patterns for emails and phone numbers
4. **International Support**: Handles formats from multiple countries

### Social Links
- Exact domain matching (reduces false positives)
- Validates against known social media domains
- Filters out affiliate/redirect links

## Limitations

- **JavaScript-Heavy Sites**: The scraper uses requests + BeautifulSoup, which cannot execute JavaScript. For JS-heavy sites, the scraper will log this limitation but still extract available static content.
- **Login-Protected Sites**: Automatically detected and handled gracefully. Only publicly accessible content can be scraped.
- **Anti-Bot Protection**: Sites with Cloudflare or similar protection may block requests (403 errors). This is logged in metadata.
- **Rate Limiting**: The scraper respects robots.txt and includes reasonable delays, but aggressive crawling may still trigger rate limiting on some sites.
- **Data Quality**: Extraction quality depends on website structure. Well-structured sites yield better results.

## Error Handling

The scraper handles various error scenarios:
- **Timeouts**: Logged in `metadata.errors_or_limitations`
- **Broken Links**: Skipped with warning logged
- **Redirects**: Followed automatically
- **Non-HTML Content**: Skipped (PDFs, images, etc.)
- **Robots.txt Restrictions**: Noted and logged (proceeds for public pages)
- **403 Forbidden**: Logged when sites block access
- **Login Required**: Detected and handled with clear messaging

All errors and limitations are recorded in the `metadata.errors_or_limitations` field of the output.

## Best Practices

1. **Respectful Scraping**: The scraper includes a User-Agent header and respects robots.txt
2. **Rate Limiting**: Consider adding delays between requests for high-volume use
3. **Error Monitoring**: Check `metadata.errors_or_limitations` to understand scraping limitations
4. **Login Detection**: The scraper automatically handles login-protected sites - no action needed
5. **Validation**: Always validate extracted data before using it for business decisions
6. **International Sites**: The scraper handles international formats, but results may vary by region

## International Support

The scraper is designed to work with companies from any region:

- **Phone Numbers**: Supports US, India, Europe, UK formats
- **Addresses**: Handles various international address formats
- **Emails**: Standard email format detection
- **Social Links**: Recognizes major platforms globally

## License

This scraper is built for DeepThought pharma intelligence firm. Use responsibly and in accordance with website terms of service and applicable laws.

## Support

For issues or questions, please refer to the code documentation or contact the development team.
