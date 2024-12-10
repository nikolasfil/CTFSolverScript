# mock_pwn.py
class MockPwn:
    pass

import sys
sys.modules['pwn'] = MockPwn()
