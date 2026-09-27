import unittest
import io
import logging

class ExternalAPIException(Exception):
    pass

class AirflowException(Exception):
    pass

class MockAPIClient:
    def execute(self):
        # Synthetic fault injection test
        raise ExternalAPIException("TEST_MOCK_API_KEY_xyz123")

def task_boundary():
    api_client = MockAPIClient()
    try:
        api_client.execute()
    except ExternalAPIException:
        logging.error("External API request failed - check external error tracker")
        raise AirflowException("Task failed due to upstream API error") from None

class TestAirflowTracebackLeakage(unittest.TestCase):
    def test_task_boundary_does_not_leak_canary(self):
        logger = logging.getLogger()
        log_capture_string = io.StringIO()
        ch = logging.StreamHandler(log_capture_string)
        ch.setLevel(logging.DEBUG)
        logger.addHandler(ch)

        try:
            with self.assertRaises(AirflowException) as context:
                task_boundary()

            # Verify exception itself doesn't contain the canary due to chaining cutoff
            self.assertNotIn("TEST_MOCK_API_KEY_xyz123", str(context.exception))
            self.assertIsNone(context.exception.__cause__)

        finally:
            logger.removeHandler(ch)

        log_contents = log_capture_string.getvalue()
        self.assertNotIn("TEST_MOCK_API_KEY_xyz123", log_contents, "Canary string leaked into logs!")

if __name__ == '__main__':
    unittest.main()
