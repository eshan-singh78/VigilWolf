"""Tests for the capture engine module."""
import pytest
from hypothesis import given, strategies as st, settings
from plugins.capture_engine import CaptureEngine


class TestCaptureEngineProperties:
    """Property-based tests for capture engine."""
    
    @given(html1=st.text(), html2=st.text())
    @settings(max_examples=100)
    def test_html_comparison_determinism(self, html1, html2):
        """Property 12: HTML comparison is deterministic.
        
        Feature: domain-monitoring, Property 12: HTML comparison is deterministic
        Validates: Requirements 3.3
        
        For any two HTML strings, comparing them multiple times should 
        always yield the same result (changed or unchanged).
        """
        engine = CaptureEngine()
        
        # Compare the same HTML strings multiple times
        result1 = engine.compare_html(html1, html2)
        result2 = engine.compare_html(html1, html2)
        result3 = engine.compare_html(html1, html2)
        
        # All results should be identical
        assert result1 == result2 == result3, \
            "HTML comparison should be deterministic"



class TestCaptureEngineUnit:
    """Unit tests for capture engine."""
    
    def test_html_comparison_identical(self):
        """Test HTML comparison with identical strings."""
        engine = CaptureEngine()
        html = "<html><body>Test</body></html>"
        
        # Identical HTML should return False (no change)
        assert engine.compare_html(html, html) == False
    
    def test_html_comparison_different(self):
        """Test HTML comparison with different strings."""
        engine = CaptureEngine()
        html1 = "<html><body>Test1</body></html>"
        html2 = "<html><body>Test2</body></html>"
        
        # Different HTML should return True (changed)
        assert engine.compare_html(html1, html2) == True
    
    def test_html_comparison_empty(self):
        """Test HTML comparison with empty strings."""
        engine = CaptureEngine()
        
        # Empty strings should be identical
        assert engine.compare_html("", "") == False
        
        # Empty vs non-empty should be different
        assert engine.compare_html("", "<html></html>") == True
    
    def test_asset_url_extraction_css(self):
        """Test extraction of CSS asset URLs."""
        engine = CaptureEngine()
        html = '''
        <html>
            <head>
                <link rel="stylesheet" href="/styles/main.css">
                <link rel="stylesheet" href="https://example.com/theme.css">
            </head>
        </html>
        '''
        base_url = "https://example.com"
        
        urls = engine.extract_asset_urls(html, base_url)
        
        assert "https://example.com/styles/main.css" in urls
        assert "https://example.com/theme.css" in urls
    
    def test_asset_url_extraction_javascript(self):
        """Test extraction of JavaScript asset URLs."""
        engine = CaptureEngine()
        html = '''
        <html>
            <body>
                <script src="/js/app.js"></script>
                <script src="https://cdn.example.com/lib.js"></script>
            </body>
        </html>
        '''
        base_url = "https://example.com"
        
        urls = engine.extract_asset_urls(html, base_url)
        
        assert "https://example.com/js/app.js" in urls
        assert "https://cdn.example.com/lib.js" in urls
    
    def test_asset_url_extraction_images(self):
        """Test extraction of image asset URLs."""
        engine = CaptureEngine()
        html = '''
        <html>
            <body>
                <img src="/images/logo.png">
                <img src="https://example.com/photo.jpg">
            </body>
        </html>
        '''
        base_url = "https://example.com"
        
        urls = engine.extract_asset_urls(html, base_url)
        
        assert "https://example.com/images/logo.png" in urls
        assert "https://example.com/photo.jpg" in urls
    
    def test_asset_url_extraction_empty_html(self):
        """Test asset extraction with empty HTML."""
        engine = CaptureEngine()
        
        urls = engine.extract_asset_urls("", "https://example.com")
        
        assert urls == []
    
    def test_asset_url_extraction_no_assets(self):
        """Test asset extraction with HTML containing no assets."""
        engine = CaptureEngine()
        html = "<html><body><p>Just text</p></body></html>"
        
        urls = engine.extract_asset_urls(html, "https://example.com")
        
        assert urls == []
    
    def test_fetch_html_error_handling(self):
        """Test HTML fetching with invalid URL."""
        engine = CaptureEngine(timeout=1)
        
        # Invalid URL should return empty string and False
        html, success = engine.fetch_html("http://invalid-domain-that-does-not-exist-12345.com")
        
        assert html == ""
        assert success == False
    
    def test_screenshot_disabled(self):
        """Test screenshot capture when disabled."""
        engine = CaptureEngine()
        engine.screenshot_enabled = False
        
        result = engine.capture_screenshot("https://example.com", "/tmp/test.png")
        
        assert result == False
