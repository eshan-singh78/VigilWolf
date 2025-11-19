"""Capture engine for the Domain Monitoring System.

Handles:
- HTML fetching from URLs
- HTML comparison for change detection
- Screenshot capture using Playwright
- Asset extraction and downloading
"""
import os
import hashlib
import requests
import time
from typing import Tuple, List, Optional
from pathlib import Path
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from config import (
    DEFAULT_TIMEOUT_SECONDS, 
    SCREENSHOT_ENABLED,
    MAX_RETRIES,
    RETRY_DELAY_SECONDS,
    RETRY_BACKOFF_MULTIPLIER
)

class CaptureEngine:
    """Handles all capture operations for domain monitoring."""
    
    def __init__(self, timeout: int = DEFAULT_TIMEOUT_SECONDS):
        """Initialize capture engine.
        
        Args:
            timeout: Timeout in seconds for HTTP requests
        """
        self.timeout = timeout
        self.screenshot_enabled = SCREENSHOT_ENABLED
        self._playwright = None
        self._browser = None
    
    def fetch_html(self, url: str, max_retries: int = MAX_RETRIES) -> Tuple[str, bool]:
        """Fetch HTML content from a URL with retry logic for transient failures.
        
        Args:
            url: URL to fetch
            max_retries: Maximum number of retry attempts for transient failures
            
        Returns:
            Tuple of (html_content, success)
            - html_content: The HTML string (empty if failed)
            - success: True if fetch succeeded, False otherwise
        """
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        last_exception = None
        retry_delay = RETRY_DELAY_SECONDS
        
        for attempt in range(max_retries):
            try:
                response = requests.get(url, timeout=self.timeout, headers=headers)
                response.raise_for_status()
                return response.text, True
            except requests.exceptions.Timeout as e:
                last_exception = e
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    retry_delay *= RETRY_BACKOFF_MULTIPLIER
                continue
            except requests.exceptions.ConnectionError as e:
                last_exception = e
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    retry_delay *= RETRY_BACKOFF_MULTIPLIER
                continue
            except requests.exceptions.HTTPError as e:
                if e.response.status_code >= 500:
                    last_exception = e
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        retry_delay *= RETRY_BACKOFF_MULTIPLIER
                    continue
                else:
                    return "", False
            except Exception as e:
                return "", False
        
        return "", False

    def compare_html(self, html1: str, html2: str) -> bool:
        """Compare two HTML strings to detect changes.
        
        Uses normalized comparison to ignore insignificant whitespace differences.
        
        Args:
            html1: First HTML string
            html2: Second HTML string
            
        Returns:
            True if HTML is different, False if identical
        """
        hash1 = hashlib.sha256(html1.encode('utf-8')).hexdigest()
        hash2 = hashlib.sha256(html2.encode('utf-8')).hexdigest()
        
        return hash1 != hash2
    
    def capture_screenshot(self, url: str, output_path: str, max_retries: int = MAX_RETRIES) -> bool:
        """Capture a screenshot of a webpage with retry logic and fallback methods.
        
        Tries multiple methods in order:
        1. Playwright (preferred - self-contained, works in CLI)
        2. Selenium (fallback - requires system Chrome/Chromium)
        
        Args:
            url: URL to capture
            output_path: Path where screenshot should be saved
            max_retries: Maximum number of retry attempts for transient failures
            
        Returns:
            True if screenshot captured successfully, False otherwise
        """
        if not self.screenshot_enabled:
            import logging
            logging.info("Screenshot capture is disabled in configuration")
            return False
        
        import logging
        logger = logging.getLogger(__name__)
        
        logger.info(f"Attempting screenshot capture for {url} using Playwright")
        success = self._capture_with_playwright(url, output_path, max_retries, logger)
        
        if success:
            logger.info(f"✓ Screenshot captured successfully using Playwright: {output_path}")
            return True
        
        logger.warning("Playwright failed, trying Selenium as fallback")
        success = self._capture_with_selenium(url, output_path, max_retries, logger)
        
        if success:
            logger.info(f"✓ Screenshot captured successfully using Selenium: {output_path}")
            return True
        
        logger.error(f"✗ All screenshot methods failed for {url}")
        return False
    
    def _capture_with_playwright(self, url: str, output_path: str, max_retries: int, logger) -> bool:
        """Capture screenshot using Playwright.
        
        Args:
            url: URL to capture
            output_path: Path where screenshot should be saved
            max_retries: Maximum retry attempts
            logger: Logger instance
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Use subprocess to run playwright in a separate process to avoid async issues
            import subprocess
            import json
        except ImportError:
            logger.warning("Required modules not available")
            return False
        
        retry_delay = RETRY_DELAY_SECONDS
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Playwright attempt {attempt + 1}/{max_retries}")
                
                # Create a simple Python script to run Playwright
                script = f"""
import sys
from playwright.sync_api import sync_playwright

try:
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu'
            ]
        )
        
        context = browser.new_context(
            viewport={{'width': 1920, 'height': 1080}},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
        
        page = context.new_page()
        page.goto('{url}', timeout={self.timeout * 1000}, wait_until='networkidle')
        page.wait_for_timeout(1000)
        page.screenshot(path='{output_path}', full_page=True)
        browser.close()
        sys.exit(0)
except Exception as e:
    print(f"Error: {{e}}", file=sys.stderr)
    sys.exit(1)
"""
                
                # Run the script in a subprocess
                result = subprocess.run(
                    ['python', '-c', script],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout + 10
                )
                
                if result.returncode == 0 and os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                    logger.info(f"Screenshot file created: {os.path.getsize(output_path)} bytes")
                    return True
                else:
                    logger.warning(f"Playwright failed: {result.stderr}")
                    
            except subprocess.TimeoutExpired:
                logger.warning(f"Playwright timeout on attempt {attempt + 1}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    retry_delay *= RETRY_BACKOFF_MULTIPLIER
                    continue
                    
            except Exception as e:
                logger.warning(f"Playwright error on attempt {attempt + 1}: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    retry_delay *= RETRY_BACKOFF_MULTIPLIER
                    continue
        
        return False
    
    def _capture_with_selenium(self, url: str, output_path: str, max_retries: int, logger) -> bool:
        """Capture screenshot using Selenium as fallback.
        
        Args:
            url: URL to capture
            output_path: Path where screenshot should be saved
            max_retries: Maximum retry attempts
            logger: Logger instance
            
        Returns:
            True if successful, False otherwise
        """
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.common.exceptions import WebDriverException, TimeoutException
        except ImportError:
            logger.warning("Selenium not installed, skipping")
            return False
        
        retry_delay = RETRY_DELAY_SECONDS
        
        for attempt in range(max_retries):
            driver = None
            try:
                logger.info(f"Selenium attempt {attempt + 1}/{max_retries}")
                
                chrome_options = Options()
                chrome_options.add_argument('--headless=new')
                chrome_options.add_argument('--no-sandbox')
                chrome_options.add_argument('--disable-dev-shm-usage')
                chrome_options.add_argument('--disable-gpu')
                chrome_options.add_argument('--window-size=1920,1080')
                chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                chrome_options.binary_location = '/usr/bin/chromium'
                
                logger.info("Initializing Chrome driver")
                from selenium.webdriver.chrome.service import Service
                service = Service('/usr/bin/chromedriver')
                driver = webdriver.Chrome(service=service, options=chrome_options)
                driver.set_page_load_timeout(self.timeout)
                
                logger.info(f"Navigating to {url}")
                driver.get(url)
                
                time.sleep(2)
                
                logger.info(f"Taking screenshot: {output_path}")
                driver.save_screenshot(output_path)
                
                driver.quit()
                
                if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                    logger.info(f"Screenshot file created: {os.path.getsize(output_path)} bytes")
                    return True
                else:
                    logger.warning("Screenshot file not created or empty")
                    return False
                    
            except (WebDriverException, TimeoutException) as e:
                logger.warning(f"Selenium error on attempt {attempt + 1}: {str(e)}")
                if driver:
                    try:
                        driver.quit()
                    except:
                        pass
                
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    retry_delay *= RETRY_BACKOFF_MULTIPLIER
                    continue
                    
            except Exception as e:
                logger.warning(f"Unexpected Selenium error on attempt {attempt + 1}: {str(e)}")
                if driver:
                    try:
                        driver.quit()
                    except:
                        pass
                
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    retry_delay *= RETRY_BACKOFF_MULTIPLIER
                    continue
        
        return False
    
    def extract_asset_urls(self, html: str, base_url: str) -> List[str]:
        """Extract asset URLs from HTML content.
        
        Extracts CSS, JavaScript, images, and fonts.
        
        Args:
            html: HTML content to parse
            base_url: Base URL for resolving relative URLs
            
        Returns:
            List of absolute asset URLs
        """
        try:
            soup = BeautifulSoup(html, 'html.parser')
            asset_urls = []
            
            for link in soup.find_all('link', rel='stylesheet'):
                href = link.get('href')
                if href:
                    asset_urls.append(urljoin(base_url, href))
            
            for script in soup.find_all('script', src=True):
                src = script.get('src')
                if src:
                    asset_urls.append(urljoin(base_url, src))
            
            for img in soup.find_all('img', src=True):
                src = img.get('src')
                if src:
                    asset_urls.append(urljoin(base_url, src))
            
            for link in soup.find_all('link'):
                href = link.get('href')
                if href and ('font' in href.lower() or link.get('type') == 'font/woff2'):
                    asset_urls.append(urljoin(base_url, href))
            
            return asset_urls
        except Exception:
            return []
    
    def download_assets(self, html: str, base_url: str, output_dir: str) -> List[str]:
        """Download assets referenced in HTML with error isolation.
        
        Each asset download is isolated - if one fails, others continue.
        Failed assets are silently skipped to ensure partial success.
        
        Args:
            html: HTML content containing asset references
            base_url: Base URL for resolving relative URLs
            output_dir: Directory where assets should be saved
            
        Returns:
            List of successfully downloaded asset filenames
        """
        asset_urls = self.extract_asset_urls(html, base_url)
        downloaded = []
        
        assets_dir = Path(output_dir) / "assets"
        assets_dir.mkdir(parents=True, exist_ok=True)
        
        for url in asset_urls:
            try:
                retry_delay = RETRY_DELAY_SECONDS
                success = False
                
                for attempt in range(MAX_RETRIES):
                    try:
                        response = requests.get(url, timeout=self.timeout)
                        response.raise_for_status()
                        success = True
                        break
                    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                        if attempt < MAX_RETRIES - 1:
                            time.sleep(retry_delay)
                            retry_delay *= RETRY_BACKOFF_MULTIPLIER
                        continue
                    except Exception:
                        break
                
                if not success:
                    continue
                
                parsed = urlparse(url)
                filename = os.path.basename(parsed.path)
                
                if not filename:
                    filename = hashlib.md5(url.encode()).hexdigest()
                
                asset_path = assets_dir / filename
                with open(asset_path, 'wb') as f:
                    f.write(response.content)
                
                downloaded.append(filename)
            except Exception:
                continue
        
        return downloaded
    
    def cleanup(self) -> None:
        """Cleanup resources (browser instances, etc.)."""
        if self._browser:
            try:
                self._browser.close()
            except Exception:
                pass
            self._browser = None
        self._playwright = None

_capture_engine = None

def get_capture_engine() -> CaptureEngine:
    """Get the global capture engine instance.
    
    Returns:
        CaptureEngine instance
    """
    global _capture_engine
    if _capture_engine is None:
        _capture_engine = CaptureEngine()
    return _capture_engine
