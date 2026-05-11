"""
VaultSecure Password Manager - Test Suite

This package contains comprehensive tests for the VaultSecure application:
- test_unit.py: Unit tests for individual functions
- test_integration.py: Integration tests for complete workflows
- test_security.py: Security and penetration tests

Usage:
    python -m pytest tests/ -v
    python run_tests.py
"""

import sys
import os
from pathlib import Path

# Ensure parent directory is in path for imports
parent_dir = Path(__file__).parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

# Test configuration
TEST_CONFIG = {
    'verbose': True,
    'buffer_output': True,
    'fail_fast': False,
    'test_timeout': 30,  # seconds
}

# Common test utilities
def setup_test_environment():
    """Setup common test environment"""
    # Disable GUI popups during testing
    os.environ['QT_QPA_PLATFORM'] = 'offscreen'
    
    # Set test mode flag
    os.environ['VAULTSECURE_TEST_MODE'] = '1'

def cleanup_test_environment():
    """Cleanup test environment"""
    # Remove test environment variables
    os.environ.pop('VAULTSECURE_TEST_MODE', None)
    os.environ.pop('QT_QPA_PLATFORM', None)

# Version info for test tracking
__version__ = '1.0.0'
__test_suites__ = ['unit', 'integration', 'security']

# Make utilities available at package level
__all__ = [
    'setup_test_environment',
    'cleanup_test_environment',
    'TEST_CONFIG',
    '__version__',
    '__test_suites__'
]