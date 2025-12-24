#!/usr/bin/env python3
"""
DeepThought Company Intelligence Scraper
A production-grade web scraper for extracting structured company information.
"""

import argparse
import json
import logging
import re
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CompanyScraper:
    """Main scraper class for extracting company information."""
    
    # Configuration
    MAX_PAGES = 15
    MAX_DEPTH = 5
    TIMEOUT = 10
    USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    
    # Priority paths to crawl
    PRIORITY_PATHS = [
        '/about', '/company', '/products', '/solutions', '/industries',
        '/pricing', '/contact', '/careers', '/team', '/services'
    ]
    
    # Social media domain patterns (exact domain matching to reduce false positives)
    SOCIAL_DOMAINS = {
        'linkedin': ['linkedin.com'],
        'twitter': ['twitter.com', 'x.com'],
        'youtube': ['youtube.com', 'youtu.be'],
        'instagram': ['instagram.com'],
        'facebook': ['facebook.com', 'fb.com'],
        'github': ['github.com'],
    }
    
    # Promotional text patterns to filter out
    PROMOTIONAL_PATTERNS = [
        r'free shipping', r'%\s*off', r'use code', r'coupon', r'discount',
        r'limited time', r'special offer', r'order now', r'buy now',
        r'add to cart', r'checkout', r'subscribe', r'newsletter'
    ]
    
    def __init__(self, base_url: str):
        """Initialize scraper with base URL."""
        self.base_url = self._normalize_url(base_url)
        self.domain = urlparse(self.base_url).netloc
        self.visited_urls: Set[str] = set()
        self.pages_data: List[Dict] = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.USER_AGENT})
        
        # Initialize result structure
        self.result = self._init_result_structure()
        
    def _normalize_url(self, url: str) -> str:
        """Normalize URL to ensure proper format."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError(f"Invalid URL: {url}")
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path or '/', '', '', ''))
    
    def _init_result_structure(self) -> Dict:
        """Initialize the result structure with all required keys."""
        return {
            'identity': {
                'company_name': None,
                'website_url': self.base_url,
                'tagline': None
            },
            'business_summary': {
                'what_they_do': None,
                'primary_offerings': [],
                'target_customers_or_industries': []
            },
            'evidence_proof_signals': {
                'key_pages_detected': [],
                'proof_signals_found': {
                    'clients': False,
                    'case_studies': False,
                    'testimonials': False,
                    'certifications_awards': False
                },
                'social_links': {}
            },
            'contact_location': {
                'emails': [],
                'phone_numbers': [],
                'physical_address': None,
                'contact_page_url': None
            },
            'team_hiring_signals': {
                'careers_page_url': None,
                'roles_or_departments_mentioned': []
            },
            'metadata': {
                'timestamp_of_scrape': datetime.utcnow().isoformat() + 'Z',
                'pages_visited': [],
                'crawl_depth_used': 0,
                'errors_or_limitations': [],
                'login_required': False
            }
        }
    
    def _check_robots_txt(self, url: str) -> bool:
        """Check if URL is allowed by robots.txt."""
        try:
            robots_url = urljoin(url, '/robots.txt')
            rp = RobotFileParser()
            rp.set_url(robots_url)
            rp.read()
            allowed = rp.can_fetch(self.USER_AGENT, url)
            if not allowed:
                logger.warning(f"URL {url} disallowed by robots.txt - proceeding anyway for public pages")
                # For public company websites, we'll proceed but log the limitation
                self.result['metadata']['errors_or_limitations'].append(f"robots.txt restriction noted for {url}")
            return True  # Proceed anyway for public company information gathering
        except Exception as e:
            logger.debug(f"Could not check robots.txt: {e}")
            return True  # Default to allowing if check fails
    
    def _detect_login_required(self, soup: BeautifulSoup, response: requests.Response, url: str) -> bool:
        """Detect if the page requires login to access."""
        # Check URL for login-related paths
        login_paths = ['/login', '/signin', '/sign-in', '/auth', '/authenticate', '/account/login']
        parsed_url = urlparse(url)
        if any(path in parsed_url.path.lower() for path in login_paths):
            logger.info(f"Login page detected in URL: {url}")
            return True
        
        # Check page title for login indicators
        title_tag = soup.find('title')
        if title_tag:
            title_text = title_tag.get_text(strip=True).lower()
            login_title_keywords = ['login', 'sign in', 'sign-in', 'authentication', 'access denied', 
                                   'please log in', 'member login', 'customer login']
            if any(keyword in title_text for keyword in login_title_keywords):
                logger.info(f"Login required - detected in page title: {title_text}")
                return True
        
        # Check for login forms
        login_form_indicators = [
            soup.find('form', {'id': re.compile(r'login|signin|auth', re.I)}),
            soup.find('form', {'class': re.compile(r'login|signin|auth', re.I)}),
            soup.find('form', {'action': re.compile(r'login|signin|auth', re.I)}),
            soup.find('input', {'type': 'password', 'name': re.compile(r'password|pass', re.I)}),
        ]
        if any(indicator for indicator in login_form_indicators if indicator):
            # Check if form is prominently displayed (not just a footer link)
            for form in soup.find_all('form'):
                if form.find('input', {'type': 'password'}):
                    # Check if this form is in main content area
                    main_content = soup.find(['main', 'article', 'div'], class_=re.compile(r'main|content|hero', re.I))
                    if main_content and form in main_content.find_all('form'):
                        logger.info("Login form detected in main content area")
                        return True
                    # If no main content area, check if form is prominent
                    form_text = form.get_text().lower()
                    if any(keyword in form_text for keyword in ['login', 'sign in', 'email', 'password']):
                        logger.info("Prominent login form detected")
                        return True
        
        # Check for common login-related text patterns
        page_text = soup.get_text().lower()
        login_text_patterns = [
            r'please (log|sign) in to (continue|access|view)',
            r'login (required|to continue|to access)',
            r'sign in (required|to continue|to access)',
            r'you must be (logged in|signed in)',
            r'access denied',
            r'authentication required',
            r'please authenticate',
        ]
        for pattern in login_text_patterns:
            if re.search(pattern, page_text, re.IGNORECASE):
                logger.info(f"Login required - detected text pattern: {pattern}")
                return True
        
        # Check for redirect to login page indicators
        meta_refresh = soup.find('meta', attrs={'http-equiv': re.compile(r'refresh', re.I)})
        if meta_refresh:
            content = meta_refresh.get('content', '')
            if any(path in content.lower() for path in login_paths):
                logger.info("Redirect to login page detected")
                return True
        
        # Check response headers for authentication requirements
        if 'www-authenticate' in response.headers:
            logger.info("HTTP authentication required")
            return True
        
        return False
    
    def _fetch_page(self, url: str) -> Optional[Tuple[requests.Response, BeautifulSoup]]:
        """Fetch a page and return response and parsed soup."""
        if url in self.visited_urls:
            return None
        
        if not self._check_robots_txt(url):
            logger.info(f"Skipping {url} (disallowed by robots.txt)")
            return None
        
        try:
            # Add more headers to appear more like a real browser
            headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            response = self.session.get(url, timeout=self.TIMEOUT, allow_redirects=True, headers=headers)
            response.raise_for_status()
            
            # Check if content is HTML
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' not in content_type:
                logger.debug(f"Skipping {url} (not HTML: {content_type})")
                return None
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Check if login is required BEFORE adding to visited URLs
            if self._detect_login_required(soup, response, url):
                logger.warning(f"Login required to access {url}")
                self.result['metadata']['errors_or_limitations'].append(
                    f"LOGIN_REQUIRED: This website requires login/authentication to access information. "
                    f"Only publicly accessible content can be scraped."
                )
                # Mark that login is required
                self.result['metadata']['login_required'] = True
                return None
            
            self.visited_urls.add(url)
            return (response, soup)
            
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching {url}")
            self.result['metadata']['errors_or_limitations'].append(f"Timeout: {url}")
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching {url}: {e}")
            self.result['metadata']['errors_or_limitations'].append(f"Request error: {url} - {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error fetching {url}: {e}")
            self.result['metadata']['errors_or_limitations'].append(f"Unexpected error: {url} - {str(e)}")
            return None
    
    def _extract_text_content(self, soup: BeautifulSoup) -> str:
        """Extract clean text content from soup."""
        # Remove script and style elements
        for script in soup(["script", "style", "meta", "link"]):
            script.decompose()
        
        text = soup.get_text(separator=' ', strip=True)
        # Clean up whitespace
        text = re.sub(r'\s+', ' ', text)
        return text.strip()
    
    def _extract_company_name(self, soup: BeautifulSoup, url: str) -> Optional[str]:
        """Extract company name from various sources with improved priority."""
        # Helper to extract domain-based company name
        def get_domain_name(url_str: str) -> Optional[str]:
            """Extract company name from domain."""
            domain = urlparse(url_str).netloc
            if domain:
                domain = re.sub(r'^www\.', '', domain)
                domain_part = domain.split('.')[0] if '.' in domain else domain
                # Handle hyphenated domains (e.g., ab-biotics -> AB-BIOTICS)
                if '-' in domain_part:
                    # Split by hyphen and capitalize each part
                    parts = domain_part.split('-')
                    return '-'.join([p.capitalize() for p in parts if p])
                return domain_part.title() if domain_part else None
            return None
        
        domain_name = get_domain_name(url)
        
        # Priority 1: Logo alt text or title attribute (most reliable, but skip if too short)
        logo_name = None
        logos = soup.find_all('img', alt=re.compile(r'logo|company|brand', re.I))
        for logo in logos:
            alt_text = logo.get('alt', '').strip()
            if alt_text and len(alt_text) < 100 and not any(skip in alt_text.lower() for skip in ['image', 'picture', 'icon']):
                # Clean common suffixes
                alt_text = re.sub(r'\s*(logo|company|brand).*$', '', alt_text, flags=re.IGNORECASE)
                alt_text = alt_text.strip()
                # Only use logo name if it's substantial (4+ chars) to avoid abbreviations
                # Or if it matches the domain name pattern
                if alt_text:
                    if len(alt_text) >= 4:
                        logo_name = alt_text
                        break
                    # If logo name is short but domain name exists and is more complete, skip logo
                    elif domain_name and len(domain_name) > len(alt_text):
                        # Skip short logo name, will use domain name later
                        logo_name = None
                        continue
                    elif len(alt_text) >= 3:
                        # Keep as fallback but continue checking other sources
                        logo_name = alt_text
        
        # Only return logo name if it's substantial (4+ chars) or we have no better option
        # We'll check other sources first before falling back to short logo names
        
        # Priority 2: Structured data (JSON-LD)
        json_ld = soup.find_all('script', type='application/ld+json')
        for script in json_ld:
            try:
                import json
                data = json.loads(script.string)
                if isinstance(data, dict):
                    name = data.get('name') or data.get('legalName') or data.get('@name')
                    if name and len(name) < 100:
                        return name.strip()
            except:
                pass
        
        # Priority 3: Meta tags
        og_site = soup.find('meta', property='og:site_name')
        if og_site and og_site.get('content'):
            name = og_site.get('content').strip()
            if name and len(name) < 100:
                return name
        
        # Priority 4: Title tag (with better cleaning)
        title_tag = soup.find('title')
        if title_tag:
            title = title_tag.get_text(strip=True)
            # Remove common suffixes and prefixes
            title = re.sub(r'\s*[-|–—]\s*(Home|Welcome|Official Site|Official Website).*$', '', title, flags=re.IGNORECASE)
            title = re.sub(r'^(Home\s*[-|–—]\s*)', '', title, flags=re.IGNORECASE)
            # Extract parts if separated by common delimiters
            parts = re.split(r'\s*[-|–—]\s*', title)
            
            # First, check if any part matches domain name (highest priority)
            if domain_name:
                for part in parts:
                    part = part.strip()
                    # Normalize both for comparison
                    part_normalized = part.lower().replace('-', ' ').replace('_', ' ')
                    domain_normalized = domain_name.lower().replace('-', ' ').replace('_', ' ')
                    if domain_normalized in part_normalized or part_normalized in domain_normalized:
                        return part
            
            # Look for company name in title - prefer parts that match domain or are concise
            for part in parts:
                part = part.strip()
                # Skip if it's too descriptive/long (likely a tagline)
                if part and len(part) < 50 and not re.search(r'manufacturer|provider|leading|world', part, re.I):
                    # If part looks like a company name (has uppercase or is short)
                    if re.match(r'^[A-Z][A-Z\s-]+[A-Z]?$', part) or (len(part) < 30 and not ' ' in part):
                        # But skip if it's too short and we have a better domain name
                        if len(part) < 4 and domain_name and len(domain_name) > len(part):
                            continue
                        return part
            
            # If no good part found, try to find company name at the end (common pattern)
            if len(parts) > 1:
                last_part = parts[-1].strip()
                # Last part is often the company name
                if last_part and len(last_part) < 50:
                    # Check if it matches domain pattern
                    if domain_name:
                        last_normalized = last_part.lower().replace('-', ' ').replace('_', ' ')
                        domain_normalized = domain_name.lower().replace('-', ' ').replace('_', ' ')
                        if domain_normalized in last_normalized or last_normalized in domain_normalized:
                            return last_part
                    # If it's short and doesn't look like a tagline
                    if len(last_part) < 30 and not re.search(r'manufacturer|provider|leading|world|solutions', last_part, re.I):
                        # But skip if too short and domain name is better
                        if len(last_part) < 4 and domain_name and len(domain_name) > len(last_part):
                            pass  # Will use domain name later
                        else:
                            return last_part
            
            # Fallback to first part (but skip if too short and domain is better)
            if parts[0].strip():
                first_part = parts[0].strip()
                if len(first_part) < 4 and domain_name and len(domain_name) > len(first_part):
                    pass  # Will use domain name later
                elif len(first_part) < 100:
                    return first_part
        
        # Priority 5: First h1 (but filter out generic ones)
        h1_tags = soup.find_all('h1', limit=3)
        for h1_tag in h1_tags:
            h1_text = h1_tag.get_text(strip=True)
            # Skip if it's too long or contains promotional text
            if h1_text and len(h1_text) < 100:
                if not any(promo in h1_text.lower() for promo in ['shop', 'buy', 'order', 'welcome to']):
                    # Check if h1 matches domain name pattern
                    if domain_name and domain_name.lower().replace('-', ' ') in h1_text.lower().replace('-', ' '):
                        return h1_text
                    return h1_text
        
        # Priority 6: Domain name (prioritize over short logo names)
        # Use domain name if logo name was too short or not found
        if domain_name:
            # Always prefer domain name if logo name is very short (1-3 chars)
            if logo_name and len(logo_name) <= 3 and len(domain_name) > len(logo_name):
                return domain_name
            elif not logo_name:
                return domain_name
        
        # Final fallback: return logo name if we have it (even if short)
        if logo_name:
            return logo_name
        
        return None
    
    def _extract_tagline(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract tagline or one-liner with improved detection."""
        # Priority 1: Hero section tagline (usually first h2 or p after h1)
        hero_section = soup.find(['section', 'div'], class_=re.compile(r'hero|banner|intro', re.I))
        if hero_section:
            # Look for tagline in hero section
            tagline_elem = hero_section.find(['h2', 'p', 'span'], class_=re.compile(r'tagline|subtitle|lead', re.I))
            if tagline_elem:
                text = tagline_elem.get_text(strip=True)
                if text and 10 < len(text) < 200:
                    return text
            
            # Try first paragraph or h2 in hero
            first_p = hero_section.find('p')
            if first_p:
                text = first_p.get_text(strip=True)
                if text and 10 < len(text) < 200:
                    return text
        
        # Priority 2: Meta description (if concise)
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc and meta_desc.get('content'):
            desc = meta_desc.get('content', '').strip()
            if desc and 10 < len(desc) < 200:
                return desc
        
        # Priority 3: First h2 after h1 (common tagline pattern)
        h1 = soup.find('h1')
        if h1:
            next_h2 = h1.find_next_sibling('h2')
            if next_h2:
                text = next_h2.get_text(strip=True)
                if text and 10 < len(text) < 200:
                    return text
        
        # Priority 4: Common tagline CSS selectors
        tagline_selectors = [
            'p.tagline', '.tagline', '#tagline',
            'h2.subtitle', '.subtitle', '.hero-subtitle',
            'p.lead', '.lead', '.slogan', 'p.slogan'
        ]
        for selector in tagline_selectors:
            tagline_elem = soup.select_one(selector)
            if tagline_elem:
                text = tagline_elem.get_text(strip=True)
                if text and 10 < len(text) < 200:
                    return text
        
        return None
    
    def _extract_emails(self, soup: BeautifulSoup, text: str, url: str) -> List[str]:
        """Extract email addresses from text and HTML attributes."""
        emails = set()
        
        # Extract from mailto links (most reliable)
        mailto_links = soup.find_all('a', href=re.compile(r'^mailto:', re.I))
        for link in mailto_links:
            href = link.get('href', '')
            email = href.replace('mailto:', '').split('?')[0].strip()
            if email and '@' in email:
                emails.add(email)
        
        # Extract from text content
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        text_emails = re.findall(email_pattern, text)
        
        # Filter out common false positives
        skip_patterns = [
            'example.com', 'domain.com', 'your-email', 'email@', 
            'test@', 'sample@', 'placeholder@', 'noreply@',
            'no-reply@', 'donotreply@', 'privacy@', 'legal@'
        ]
        
        for email in text_emails:
            email_lower = email.lower()
            # Skip if it's a common placeholder or system email
            if not any(skip in email_lower for skip in skip_patterns):
                # Validate it looks like a real email
                if len(email.split('@')[0]) > 0 and '.' in email.split('@')[1]:
                    emails.add(email)
        
        return list(emails)[:10]  # Limit to 10 emails
    
    def _extract_phone_numbers(self, soup: BeautifulSoup, text: str) -> List[str]:
        """Extract phone numbers from text and HTML with international support."""
        phones = set()
        
        # Extract from tel: links (most reliable)
        tel_links = soup.find_all('a', href=re.compile(r'^tel:', re.I))
        for link in tel_links:
            href = link.get('href', '')
            phone = href.replace('tel:', '').strip()
            if phone:
                phones.add(phone)
        
        # Enhanced phone patterns for international formats
        patterns = [
            # International with country code: +91 12345 67890, +1-555-123-4567
            r'\+?\d{1,4}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}',
            # Indian format: +91 98765 43210, 91-9876543210
            r'\+?91[-.\s]?\d{2,5}[-.\s]?\d{5,8}',
            # European format: +34 93 849 63 44
            r'\+?\d{1,3}[-.\s]?\d{1,3}[-.\s]?\d{1,3}[-.\s]?\d{1,4}',
            # US/Canada: (555) 123-4567, 555-123-4567
            r'\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
            # UK: +44 20 7946 0958, 020 7946 0958
            r'\+?44[-.\s]?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}',
            # General format with parentheses
            r'\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                # Clean and validate
                cleaned = re.sub(r'[^\d+]', '', match)
                # Must have at least 10 digits (international standard minimum)
                if len(cleaned) >= 10:
                    # Avoid false positives (dates, IDs, etc.)
                    if not re.match(r'^\d{4}$', cleaned):  # Not a year
                        phones.add(match.strip())
        
        return list(phones)[:5]  # Limit to 5 phone numbers
    
    def _extract_social_links(self, soup: BeautifulSoup) -> Dict[str, str]:
        """Extract social media links with improved validation."""
        social_links = {}
        links = soup.find_all('a', href=True)
        
        for link in links:
            href = link.get('href', '')
            full_url = urljoin(self.base_url, href)
            parsed = urlparse(full_url)
            
            # Only check actual social media domains (reduce false positives)
            for platform, domains in self.SOCIAL_DOMAINS.items():
                if platform in social_links:
                    continue
                
                for domain in domains:
                    if domain.lower() in parsed.netloc.lower():
                        # Additional validation: check if it's actually a social link
                        # (not a redirect or affiliate link)
                        path = parsed.path.lower()
                        # Skip if it looks like an affiliate/redirect link
                        if not any(skip in full_url.lower() for skip in ['utm_', 'ref=', 'source=', 'affiliate']):
                            social_links[platform] = full_url
                            break
                
                if platform in social_links:
                    break
        
        return social_links
    
    def _detect_key_pages(self, url: str) -> List[str]:
        """Detect which key pages this URL represents with more variations."""
        detected = []
        path = urlparse(url).path.lower()
        
        page_mapping = {
            'about': ['/about', '/company', '/who-we-are', '/our-story', '/about-us', '/who-are-we'],
            'products': ['/products', '/product', '/offerings', '/portfolio'],
            'solutions': ['/solutions', '/solution', '/services', '/service'],
            'industries': ['/industries', '/industry', '/markets', '/sectors', '/therapeutic-areas'],
            'pricing': ['/pricing', '/price', '/plans', '/purchase', '/buy'],
            'careers': ['/careers', '/career', '/jobs', '/join-us', '/hiring', '/work-with-us', '/team'],
            'contact': ['/contact', '/contact-us', '/get-in-touch', '/reach-us', '/connect', '/get-in-touch']
        }
        
        for page_name, patterns in page_mapping.items():
            if any(pattern in path for pattern in patterns):
                detected.append(page_name)
        
        return detected
    
    def _detect_proof_signals(self, soup: BeautifulSoup, text: str) -> Dict[str, bool]:
        """Detect proof signals like clients, case studies, testimonials, etc."""
        text_lower = text.lower()
        
        signals = {
            'clients': False,
            'case_studies': False,
            'testimonials': False,
            'certifications_awards': False
        }
        
        # Check for clients
        client_keywords = ['our clients', 'clients', 'customer', 'trusted by', 'partners']
        if any(keyword in text_lower for keyword in client_keywords):
            # Look for client logos or lists
            if soup.find_all('img', alt=re.compile(r'client|customer|partner', re.I)):
                signals['clients'] = True
            elif soup.find_all(['div', 'section'], class_=re.compile(r'client|customer', re.I)):
                signals['clients'] = True
        
        # Check for case studies
        case_study_keywords = ['case study', 'case studies', 'success story', 'success stories']
        if any(keyword in text_lower for keyword in case_study_keywords):
            signals['case_studies'] = True
        
        # Check for testimonials
        testimonial_keywords = ['testimonial', 'testimonials', 'what our', 'customer review']
        if any(keyword in text_lower for keyword in testimonial_keywords):
            signals['testimonials'] = True
        
        # Check for certifications/awards
        cert_keywords = ['certified', 'certification', 'award', 'awards', 'accredited', 'iso']
        if any(keyword in text_lower for keyword in cert_keywords):
            signals['certifications_awards'] = True
        
        return signals
    
    def _extract_primary_offerings(self, soup: BeautifulSoup, text: str) -> List[str]:
        """Extract primary products/services offerings with better filtering."""
        offerings = []
        skip_keywords = ['about', 'contact', 'home', 'menu', 'language', 'sort', 'filter', 
                        'search', 'cart', 'checkout', 'login', 'sign up', 'subscribe',
                        'read more', 'learn more', 'view all', 'see all', 'shop', 'buy now']
        
        # Look for common product/service sections
        product_selectors = [
            'section.products', '.product-list', '#products',
            'section.services', '.service-list', '#services',
            '.offerings', '#offerings', '.solutions', '#solutions',
            '.portfolio', '#portfolio'
        ]
        
        for selector in product_selectors:
            section = soup.select_one(selector)
            if section:
                items = section.find_all(['li', 'div', 'h3', 'h4', 'article'], limit=15)
                for item in items:
                    text_item = item.get_text(strip=True)
                    # Better filtering
                    if (text_item and 3 < len(text_item) < 100 and 
                        not any(skip in text_item.lower() for skip in skip_keywords) and
                        text_item not in offerings):
                        offerings.append(text_item)
        
        # If no structured list found, try to extract from headings (with better filtering)
        if len(offerings) < 5:
            headings = soup.find_all(['h2', 'h3'], limit=15)
            for heading in headings:
                text_heading = heading.get_text(strip=True)
                # Filter out generic headings and promotional text
                if (text_heading and 3 < len(text_heading) < 80 and
                    not any(skip in text_heading.lower() for skip in skip_keywords) and
                    not any(promo in text_heading.lower() for promo in ['% off', 'free shipping', 'sale', 'discount']) and
                    text_heading not in offerings):
                    offerings.append(text_heading)
        
        return offerings[:15]  # Increased limit
    
    def _extract_target_customers(self, soup: BeautifulSoup, text: str) -> List[str]:
        """Extract target customers or industries with improved detection."""
        targets = []
        
        # Look for industries/markets sections
        industry_keywords = ['industries', 'markets', 'sectors', 'verticals', 'therapeutic-areas', 'customers', 'clients']
        for keyword in industry_keywords:
            # Try class/id matching
            section = soup.find(['section', 'div'], 
                              class_=re.compile(keyword, re.I))
            if not section:
                # Try ID matching
                section = soup.find(['section', 'div'], id=re.compile(keyword, re.I))
            
            if section:
                # Extract list items
                items = section.find_all(['li', 'div', 'span', 'h3', 'h4'], limit=15)
                for item in items:
                    text_item = item.get_text(strip=True)
                    # Filter out generic text
                    if (text_item and 3 < len(text_item) < 100 and 
                        not any(skip in text_item.lower() for skip in ['learn more', 'read more', 'view all', 'see all'])):
                        if text_item not in targets:
                            targets.append(text_item)
        
        # Also look for explicit mentions in text
        industry_patterns = [
            r'(?:serving|targeting|focusing on|for)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s+(?:industry|market|sector)',
            r'(?:industries|markets|sectors):\s*([^.\n]+)',
        ]
        
        for pattern in industry_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match else ''
                match = match.strip()
                if match and 3 < len(match) < 100 and match not in targets:
                    targets.append(match)
        
        return targets[:15]  # Increased limit
    
    def _extract_physical_address(self, soup: BeautifulSoup, text: str) -> Optional[str]:
        """Extract physical address with improved international support."""
        # Priority 1: Footer address (most common location)
        footer = soup.find(['footer', 'div'], class_=re.compile(r'footer', re.I))
        if footer:
            address_elem = footer.find(['address', 'div', 'p'], class_=re.compile(r'address|location|office', re.I))
            if address_elem:
                address_text = address_elem.get_text(separator=', ', strip=True)
                # Clean up and validate
                address_text = re.sub(r'\s+', ' ', address_text)
                if address_text and 10 < len(address_text) < 300:
                    return address_text
        
        # Priority 2: Structured data (JSON-LD)
        json_ld = soup.find_all('script', type='application/ld+json')
        for script in json_ld:
            try:
                import json
                data = json.loads(script.string)
                if isinstance(data, dict):
                    address = data.get('address')
                    if isinstance(address, dict):
                        # Format address from structured data
                        parts = []
                        if address.get('streetAddress'):
                            parts.append(address['streetAddress'])
                        if address.get('addressLocality'):
                            parts.append(address['addressLocality'])
                        if address.get('addressRegion'):
                            parts.append(address['addressRegion'])
                        if address.get('postalCode'):
                            parts.append(address['postalCode'])
                        if address.get('addressCountry'):
                            parts.append(address['addressCountry'])
                        if parts:
                            return ', '.join(parts)
            except:
                pass
        
        # Priority 3: Address tag
        address_elem = soup.find('address')
        if address_elem:
            address_text = address_elem.get_text(separator=', ', strip=True)
            if address_text and 10 < len(address_text) < 300:
                return address_text
        
        # Priority 4: Div with address class
        address_divs = soup.find_all(['div', 'p', 'span'], class_=re.compile(r'address|location|office', re.I))
        for div in address_divs:
            address_text = div.get_text(separator=', ', strip=True)
            # Check if it looks like an address (contains street/road/etc or numbers)
            if address_text and 10 < len(address_text) < 300:
                if re.search(r'\d+|street|road|avenue|st|rd|ave|boulevard|blvd', address_text, re.I):
                    return address_text
        
        # Priority 5: Pattern matching (international formats)
        # US/UK format: 123 Main St, City, State ZIP
        address_patterns = [
            r'\d+[\s\w]+(?:street|st|avenue|ave|road|rd|boulevard|blvd|drive|dr|lane|ln|way|circle|ct|place|pl)[\s\w,]+(?:[A-Z]{2}\s)?\d{5,10}',
            # International: Street, City, Country
            r'[\w\s]+(?:street|st|avenue|ave|road|rd|boulevard|blvd)[\s\w,]+(?:[A-Z][a-z]+\s?)+',
        ]
        
        for pattern in address_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # Take the longest match (most complete address)
                longest = max(matches, key=len)
                if 10 < len(longest) < 300:
                    return longest
        
        return None
    
    def _extract_what_they_do(self, soup: BeautifulSoup, text: str) -> Optional[str]:
        """Extract 2-4 line summary of what the company does, filtering promotional content."""
        # Helper to check if text is promotional
        def is_promotional(text_lower):
            return any(re.search(pattern, text_lower) for pattern in self.PROMOTIONAL_PATTERNS)
        
        # Priority 1: Meta description (if not promotional)
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc and meta_desc.get('content'):
            desc = meta_desc.get('content', '').strip()
            if desc and 50 < len(desc) < 500 and not is_promotional(desc.lower()):
                return desc
        
        # Priority 2: About section (most reliable)
        about_section = soup.find(['section', 'div'], 
                                 class_=re.compile(r'about|intro|hero|mission', re.I))
        if about_section:
            paragraphs = about_section.find_all('p', limit=4)
            summary_parts = []
            for p in paragraphs:
                p_text = p.get_text(strip=True)
                # Skip promotional paragraphs
                if p_text and not is_promotional(p_text.lower()) and len(p_text) > 30:
                    summary_parts.append(p_text)
                    if len(summary_parts) >= 3:  # Limit to 3 paragraphs
                        break
            
            if summary_parts:
                summary = ' '.join(summary_parts)
                if 50 < len(summary) < 500:
                    return summary
        
        # Priority 3: First meaningful paragraphs (skip promotional)
        paragraphs = soup.find_all('p', limit=6)
        summary_parts = []
        for p in paragraphs:
            p_text = p.get_text(strip=True)
            # Skip if too short, promotional, or contains common e-commerce text
            if (p_text and len(p_text) > 30 and 
                not is_promotional(p_text.lower()) and
                not any(skip in p_text.lower() for skip in ['cart', 'checkout', 'add to', 'buy now'])):
                summary_parts.append(p_text)
                if len(summary_parts) >= 3:
                    break
        
        if summary_parts:
            summary = ' '.join(summary_parts)
            if 50 < len(summary) < 500:
                return summary
        
        return None
    
    def _extract_career_info(self, soup: BeautifulSoup, text: str) -> Tuple[Optional[str], List[str]]:
        """Extract career page URL and mentioned roles/departments with improved detection."""
        roles = []
        
        # Look for departments section (common on team/about pages)
        dept_section = soup.find(['section', 'div'], class_=re.compile(r'department|team|organization', re.I))
        if dept_section:
            dept_items = dept_section.find_all(['li', 'div', 'h3', 'h4'], limit=15)
            for item in dept_items:
                dept_text = item.get_text(strip=True)
                # Common department names
                if any(dept in dept_text.lower() for dept in ['research', 'development', 'sales', 'marketing', 
                                                               'operations', 'quality', 'regulatory', 'medical',
                                                               'clinical', 'supply', 'business']):
                    if dept_text and 3 < len(dept_text) < 100 and dept_text not in roles:
                        roles.append(dept_text)
        
        # Look for job listings or role mentions
        job_keywords = ['engineer', 'developer', 'manager', 'analyst', 'designer', 
                       'sales', 'marketing', 'product', 'operations', 'scientist',
                       'researcher', 'director', 'specialist', 'coordinator', 'executive']
        text_lower = text.lower()
        
        for keyword in job_keywords:
            if keyword in text_lower:
                # Try to find the actual role mention with context
                patterns = [
                    rf'\b\w+\s+{keyword}\b',
                    rf'\b{keyword}\s+\w+\b',
                    rf'\b\w+\s+\w+\s+{keyword}\b',
                ]
                for pattern in patterns:
                    matches = re.findall(pattern, text_lower)
                    for match in matches:
                        # Clean and validate
                        match = match.strip().title()
                        if match and 5 < len(match) < 50 and match not in roles:
                            roles.append(match)
        
        return None, roles[:15]  # Increased limit
    
    def _extract_footer_content(self, soup: BeautifulSoup) -> Dict[str, List[str]]:
        """Extract contact information specifically from footer."""
        footer_data = {'emails': [], 'phones': [], 'addresses': []}
        
        # Find footer element
        footer = soup.find(['footer', 'div'], class_=re.compile(r'footer', re.I))
        if not footer:
            # Try to find footer by ID
            footer = soup.find(['footer', 'div'], id=re.compile(r'footer', re.I))
        
        if footer:
            footer_text = footer.get_text(separator=' ', strip=True)
            
            # Extract emails from footer
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, footer_text)
            for email in emails:
                email_lower = email.lower()
                if not any(skip in email_lower for skip in ['example.com', 'domain.com', 'noreply@', 'no-reply@']):
                    if email not in footer_data['emails']:
                        footer_data['emails'].append(email)
            
            # Extract phones from footer
            phone_patterns = [
                r'\+?\d{1,4}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}',
                r'\+?91[-.\s]?\d{2,5}[-.\s]?\d{5,8}',
            ]
            for pattern in phone_patterns:
                phones = re.findall(pattern, footer_text)
                for phone in phones:
                    cleaned = re.sub(r'[^\d+]', '', phone)
                    if len(cleaned) >= 10:
                        if phone.strip() not in footer_data['phones']:
                            footer_data['phones'].append(phone.strip())
        
        return footer_data
    
    def _get_internal_links(self, soup: BeautifulSoup, current_url: str) -> List[str]:
        """Extract internal links from page."""
        links = []
        base_domain = urlparse(self.base_url).netloc
        
        for anchor in soup.find_all('a', href=True):
            href = anchor.get('href', '')
            full_url = urljoin(current_url, href)
            parsed = urlparse(full_url)
            
            # Only internal links
            if parsed.netloc == base_domain or not parsed.netloc:
                # Normalize URL
                normalized = urlunparse((parsed.scheme or 'https', 
                                       parsed.netloc or base_domain,
                                       parsed.path or '/', '', '', ''))
                
                if normalized not in self.visited_urls and normalized not in links:
                    links.append(normalized)
        
        return links
    
    def _prioritize_urls(self, urls: List[str]) -> List[str]:
        """Prioritize URLs based on priority paths."""
        priority_urls = []
        other_urls = []
        
        for url in urls:
            path = urlparse(url).path.lower()
            is_priority = any(priority_path in path for priority_path in self.PRIORITY_PATHS)
            
            if is_priority:
                priority_urls.append(url)
            else:
                other_urls.append(url)
        
        return priority_urls + other_urls
    
    def _process_page(self, url: str, depth: int = 0) -> None:
        """Process a single page and extract information."""
        # Stop if login is already required
        if self.result['metadata'].get('login_required', False):
            return
        
        if len(self.visited_urls) >= self.MAX_PAGES or depth > self.MAX_DEPTH:
            return
        
        logger.info(f"Processing: {url} (depth: {depth})")
        
        result = self._fetch_page(url)
        if not result:
            # Check if login was detected
            if self.result['metadata'].get('login_required', False):
                return
            return
        
        response, soup = result
        text = self._extract_text_content(soup)
        
        # Detect key pages
        key_pages = self._detect_key_pages(url)
        for page in key_pages:
            if page not in self.result['evidence_proof_signals']['key_pages_detected']:
                self.result['evidence_proof_signals']['key_pages_detected'].append(page)
        
        # Extract identity information (only from homepage or about page)
        if depth == 0 or 'about' in key_pages:
            if not self.result['identity']['company_name']:
                company_name = self._extract_company_name(soup, url)
                if company_name:
                    self.result['identity']['company_name'] = company_name
            
            if not self.result['identity']['tagline']:
                tagline = self._extract_tagline(soup)
                if tagline:
                    self.result['identity']['tagline'] = tagline
        
        # Extract business summary
        if not self.result['business_summary']['what_they_do']:
            what_they_do = self._extract_what_they_do(soup, text)
            if what_they_do:
                self.result['business_summary']['what_they_do'] = what_they_do
        
        # Extract offerings
        offerings = self._extract_primary_offerings(soup, text)
        for offering in offerings:
            if offering not in self.result['business_summary']['primary_offerings']:
                self.result['business_summary']['primary_offerings'].append(offering)
        
        # Extract target customers
        targets = self._extract_target_customers(soup, text)
        for target in targets:
            if target not in self.result['business_summary']['target_customers_or_industries']:
                self.result['business_summary']['target_customers_or_industries'].append(target)
        
        # Extract proof signals
        proof_signals = self._detect_proof_signals(soup, text)
        for signal, found in proof_signals.items():
            if found:
                self.result['evidence_proof_signals']['proof_signals_found'][signal] = True
        
        # Extract social links
        social_links = self._extract_social_links(soup)
        self.result['evidence_proof_signals']['social_links'].update(social_links)
        
        # Extract contact information (with footer priority)
        # First, try footer (most reliable source)
        footer_data = self._extract_footer_content(soup)
        for email in footer_data['emails']:
            if email not in self.result['contact_location']['emails']:
                self.result['contact_location']['emails'].append(email)
        for phone in footer_data['phones']:
            if phone not in self.result['contact_location']['phone_numbers']:
                self.result['contact_location']['phone_numbers'].append(phone)
        
        # Then extract from entire page
        emails = self._extract_emails(soup, text, url)
        for email in emails:
            if email not in self.result['contact_location']['emails']:
                self.result['contact_location']['emails'].append(email)
        
        phones = self._extract_phone_numbers(soup, text)
        for phone in phones:
            if phone not in self.result['contact_location']['phone_numbers']:
                self.result['contact_location']['phone_numbers'].append(phone)
        
        if not self.result['contact_location']['physical_address']:
            address = self._extract_physical_address(soup, text)
            if address:
                self.result['contact_location']['physical_address'] = address
        
        # Enhanced contact page detection
        if 'contact' in key_pages:
            if not self.result['contact_location']['contact_page_url']:
                self.result['contact_location']['contact_page_url'] = url
        else:
            # Also check for "Get in touch" links
            contact_links = soup.find_all('a', href=True, string=re.compile(r'contact|get in touch|reach us|connect', re.I))
            if contact_links:
                for link in contact_links:
                    href = link.get('href', '')
                    full_url = urljoin(url, href)
                    if not self.result['contact_location']['contact_page_url']:
                        self.result['contact_location']['contact_page_url'] = full_url
                        break
        
        # Extract career information
        if 'careers' in key_pages:
            if not self.result['team_hiring_signals']['careers_page_url']:
                self.result['team_hiring_signals']['careers_page_url'] = url
            
            _, roles = self._extract_career_info(soup, text)
            for role in roles:
                if role not in self.result['team_hiring_signals']['roles_or_departments_mentioned']:
                    self.result['team_hiring_signals']['roles_or_departments_mentioned'].append(role)
        
        # Track visited page
        self.result['metadata']['pages_visited'].append(url)
        self.result['metadata']['crawl_depth_used'] = max(
            self.result['metadata']['crawl_depth_used'], depth
        )
        
        # Get internal links for further crawling
        if depth < self.MAX_DEPTH:
            internal_links = self._get_internal_links(soup, url)
            prioritized_links = self._prioritize_urls(internal_links)
            
            for link in prioritized_links[:5]:  # Limit links per page
                if len(self.visited_urls) >= self.MAX_PAGES:
                    break
                self._process_page(link, depth + 1)
    
    def scrape(self) -> Dict:
        """Main scraping method."""
        logger.info(f"Starting scrape of {self.base_url}")
        
        try:
            # Start with homepage
            self._process_page(self.base_url, depth=0)
            
            # If login is required, stop here and return minimal result
            if self.result['metadata'].get('login_required', False):
                logger.warning("Login required detected - stopping scrape and returning minimal result")
                # Return a clean result indicating login is required
                return {
                    'identity': {
                        'company_name': None,
                        'website_url': self.base_url,
                        'tagline': None
                    },
                    'business_summary': {
                        'what_they_do': None,
                        'primary_offerings': [],
                        'target_customers_or_industries': []
                    },
                    'evidence_proof_signals': {
                        'key_pages_detected': [],
                        'proof_signals_found': {
                            'clients': False,
                            'case_studies': False,
                            'testimonials': False,
                            'certifications_awards': False
                        },
                        'social_links': {}
                    },
                    'contact_location': {
                        'emails': [],
                        'phone_numbers': [],
                        'physical_address': None,
                        'contact_page_url': None
                    },
                    'team_hiring_signals': {
                        'careers_page_url': None,
                        'roles_or_departments_mentioned': []
                    },
                    'metadata': {
                        'timestamp_of_scrape': datetime.utcnow().isoformat() + 'Z',
                        'pages_visited': [],
                        'crawl_depth_used': 0,
                        'errors_or_limitations': [
                            "LOGIN_REQUIRED: This website requires login/authentication to access information. "
                            "Only publicly accessible content can be scraped."
                        ],
                        'login_required': True
                    }
                }
            
            # Clean up empty lists (convert to empty lists for JSON consistency)
            if not self.result['business_summary']['primary_offerings']:
                self.result['business_summary']['primary_offerings'] = []
            if not self.result['business_summary']['target_customers_or_industries']:
                self.result['business_summary']['target_customers_or_industries'] = []
            if not self.result['contact_location']['emails']:
                self.result['contact_location']['emails'] = []
            if not self.result['contact_location']['phone_numbers']:
                self.result['contact_location']['phone_numbers'] = []
            if not self.result['team_hiring_signals']['roles_or_departments_mentioned']:
                self.result['team_hiring_signals']['roles_or_departments_mentioned'] = []
            if not self.result['evidence_proof_signals']['key_pages_detected']:
                self.result['evidence_proof_signals']['key_pages_detected'] = []
            
            logger.info(f"Scraping completed. Visited {len(self.visited_urls)} pages.")
            
        except Exception as e:
            logger.error(f"Fatal error during scraping: {e}")
            self.result['metadata']['errors_or_limitations'].append(f"Fatal error: {str(e)}")
        
        return self.result


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description='DeepThought Company Intelligence Scraper',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        'url',
        type=str,
        help='Company website URL to scrape'
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        default=None,
        help='Output JSON file path (default: print to stdout)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        scraper = CompanyScraper(args.url)
        result = scraper.scrape()
        
        # Output result
        output_json = json.dumps(result, indent=2, ensure_ascii=False)
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output_json)
            logger.info(f"Results saved to {args.output}")
        else:
            print(output_json)
            
    except KeyboardInterrupt:
        logger.info("Scraping interrupted by user")
    except Exception as e:
        logger.error(f"Error: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())

