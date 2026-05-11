import unittest
import sys
import os
import time
from io import StringIO
from pathlib import Path

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def setup_test_environment():
    """Setup test environment"""
    # Import test utilities if available
    try:
        from tests import setup_test_environment as setup_env
        setup_env()
    except ImportError:
        # Fallback: set basic test environment
        os.environ['QT_QPA_PLATFORM'] = 'offscreen'
        os.environ['VAULTSECURE_TEST_MODE'] = '1'

def cleanup_test_environment():
    """Cleanup test environment"""
    try:
        from tests import cleanup_test_environment as cleanup_env
        cleanup_env()
    except ImportError:
        # Fallback cleanup
        os.environ.pop('VAULTSECURE_TEST_MODE', None)
        os.environ.pop('QT_QPA_PLATFORM', None)

def run_all_tests():
    """Run all test suites with detailed reporting"""
    
    print("=" * 60)
    print("VAULTSECURE PASSWORD MANAGER - TEST SUITE")
    print("=" * 60)
    print(f"Starting tests at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Setup test environment
    setup_test_environment()
    
    try:
        # Discover and run all tests
        loader = unittest.TestLoader()
        start_dir = 'tests'
        
        if not os.path.exists(start_dir):
            print(f"Error: Tests directory '{start_dir}' not found!")
            print("Please create the tests directory and add your test files.")
            return False
        
        # Check if test files exist
        test_files = list(Path(start_dir).glob('test_*.py'))
        if not test_files:
            print(f"Error: No test files found in '{start_dir}' directory!")
            print("Expected files: test_unit.py, test_integration.py, test_security.py")
            return False
        
        print(f"Found {len(test_files)} test file(s):")
        for test_file in test_files:
            print(f"  - {test_file.name}")
        print()
        
        suite = loader.discover(start_dir, pattern='test_*.py')
        
        # Check if any tests were discovered
        if suite.countTestCases() == 0:
            print("Error: No test cases discovered!")
            return False
        
        print(f"Discovered {suite.countTestCases()} test case(s)")
        print("-" * 60)
        
        # Custom test runner with more verbose output
        stream = StringIO()
        runner = unittest.TextTestRunner(stream=stream, verbosity=2)
        
        # Run tests with timing
        start_time = time.time()
        result = runner.run(suite)
        end_time = time.time()
        
        # Print the test output
        test_output = stream.getvalue()
        print(test_output)
        
        # Print detailed summary
        print(f"\n{'='*60}")
        print(f"TEST EXECUTION SUMMARY")
        print(f"{'='*60}")
        print(f"Tests run: {result.testsRun}")
        print(f"Failures: {len(result.failures)}")
        print(f"Errors: {len(result.errors)}")
        print(f"Skipped: {len(result.skipped) if hasattr(result, 'skipped') else 0}")
        print(f"Execution time: {end_time - start_time:.2f} seconds")
        
        if result.testsRun > 0:
            success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100)
            print(f"Success rate: {success_rate:.1f}%")
        else:
            print("No tests were run!")
            return False
        
        # Print failures details
        if result.failures:
            print(f"\n{'='*60}")
            print(f"FAILURES ({len(result.failures)}):")
            print(f"{'='*60}")
            for i, (test, traceback) in enumerate(result.failures, 1):
                print(f"{i}. {test}")
                # Extract more meaningful error message
                if 'AssertionError:' in traceback:
                    error_msg = traceback.split('AssertionError:')[-1].strip()
                    print(f"   AssertionError: {error_msg}")
                else:
                    # Show last line of traceback
                    lines = traceback.strip().split('\n')
                    print(f"   {lines[-1] if lines else 'See full output above'}")
                print()
        
        # Print errors details
        if result.errors:
            print(f"\n{'='*60}")
            print(f"ERRORS ({len(result.errors)}):")
            print(f"{'='*60}")
            for i, (test, traceback) in enumerate(result.errors, 1):
                print(f"{i}. {test}")
                # Extract error type and message
                lines = traceback.strip().split('\n')
                error_line = lines[-1] if lines else 'Unknown error'
                print(f"   {error_line}")
                print()
        
        # Test suite specific results
        if result.testsRun > 0:
            print(f"\n{'='*60}")
            print("TEST SUITE BREAKDOWN:")
            print(f"{'='*60}")
            
            # FIXED: Removed the problematic _testResults access
            # Simply show available test files instead
            for test_file in test_files:
                suite_name = test_file.stem.replace('test_', '').title()
                print(f"{suite_name} Tests: Available")
            
        # Overall result
        print(f"\n{'='*60}")
        if result.wasSuccessful():
            print("🎉 ALL TESTS PASSED! Your application is working correctly.")
            print("✅ Unit Tests: Passed")
            print("✅ Integration Tests: Passed") 
            print("✅ Security Tests: Passed")
        else:
            print("❌ SOME TESTS FAILED! Please review the failures above.")
            if result.failures:
                print(f"⚠️  {len(result.failures)} test(s) failed")
            if result.errors:
                print(f"💥 {len(result.errors)} test(s) had errors")
        print(f"{'='*60}")
        
        return result.wasSuccessful()
        
    except KeyboardInterrupt:
        print("\n\n❌ Tests interrupted by user")
        return False
    except Exception as e:
        print(f"\n\n💥 Unexpected error running tests: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Always cleanup
        cleanup_test_environment()

def run_specific_test_suite(test_type):
    """Run a specific test suite"""
    test_files = {
        'unit': 'tests/test_unit.py',
        'integration': 'tests/test_integration.py',
        'security': 'tests/test_security.py'
    }
    
    if test_type not in test_files:
        print(f"Invalid test type. Choose from: {', '.join(test_files.keys())}")
        return False
    
    test_file = test_files[test_type]
    if not os.path.exists(test_file):
        print(f"Test file {test_file} not found!")
        print(f"Please create {test_file} with your {test_type} tests.")
        return False
    
    print(f"Running {test_type.upper()} tests...")
    print("=" * 40)
    
    # Setup test environment
    setup_test_environment()
    
    try:
        # Load and run specific test suite
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromName(f'tests.test_{test_type}')
        
        if suite.countTestCases() == 0:
            print(f"No test cases found in {test_file}")
            return False
        
        print(f"Found {suite.countTestCases()} test case(s) in {test_type} suite")
        print("-" * 40)
        
        start_time = time.time()
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        end_time = time.time()
        
        print(f"\n{test_type.upper()} TEST SUMMARY:")
        print(f"Tests run: {result.testsRun}")
        print(f"Failures: {len(result.failures)}")
        print(f"Errors: {len(result.errors)}")
        print(f"Execution time: {end_time - start_time:.2f} seconds")
        
        if result.wasSuccessful():
            print(f"✅ {test_type.upper()} tests passed!")
        else:
            print(f"❌ {test_type.upper()} tests failed!")
        
        return result.wasSuccessful()
        
    except Exception as e:
        print(f"Error running {test_type} tests: {e}")
        return False
    finally:
        cleanup_test_environment()

def validate_test_environment():
    """Validate that the test environment is properly set up"""
    issues = []
    
    # Check for required directories
    if not os.path.exists('tests'):
        issues.append("Tests directory 'tests/' not found")
    
    # Check for test files
    required_files = ['tests/test_unit.py', 'tests/test_integration.py', 'tests/test_security.py']
    for file_path in required_files:
        if not os.path.exists(file_path):
            issues.append(f"Test file '{file_path}' not found")
    
    # Check for main application files
    app_files = ['vaultsecure_backend.py', 'main_window.py', 'login_screen.py']
    for file_path in app_files:
        if not os.path.exists(file_path):
            issues.append(f"Application file '{file_path}' not found")
    
    return issues

if __name__ == '__main__':
    # Validate environment first
    issues = validate_test_environment()
    if issues:
        print("❌ Test environment validation failed:")
        for issue in issues:
            print(f"  - {issue}")
        print("\nPlease fix these issues before running tests.")
        sys.exit(1)
    
    # Check command line arguments
    if len(sys.argv) > 1:
        test_type = sys.argv[1].lower()
        if test_type in ['unit', 'integration', 'security']:
            success = run_specific_test_suite(test_type)
        elif test_type == 'help':
            print("VaultSecure Password Manager - Test Runner")
            print("=" * 45)
            print("Usage:")
            print("  python run_tests.py           # Run all tests")
            print("  python run_tests.py unit      # Run unit tests only")
            print("  python run_tests.py integration # Run integration tests only")
            print("  python run_tests.py security  # Run security tests only")
            print("  python run_tests.py help      # Show this help")
            print("\nTest Files:")
            print("  tests/test_unit.py           # Unit tests")
            print("  tests/test_integration.py    # Integration tests")
            print("  tests/test_security.py       # Security/penetration tests")
            sys.exit(0)
        elif test_type == 'validate':
            # Hidden command to validate environment
            issues = validate_test_environment()
            if issues:
                print("❌ Validation issues found:")
                for issue in issues:
                    print(f"  - {issue}")
                sys.exit(1)
            else:
                print("✅ Test environment validation passed!")
                sys.exit(0)
        else:
            print(f"Unknown test type: {test_type}")
            print("Use 'python run_tests.py help' for usage information")
            sys.exit(1)
    else:
        success = run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)