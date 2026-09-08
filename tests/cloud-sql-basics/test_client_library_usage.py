import os
import unittest
from unittest.mock import MagicMock, patch

class TestGetConn(unittest.TestCase):
    @patch.dict(os.environ, {
        "DB_INSTANCE_NAME": "project:region:instance",
        "DB_USER": "test-user",
        "DB_PASS": "test-password",
        "DB_NAME": "test-db"
    })
    def test_getconn(self):
        # Setup mock connector directly without importing the real one
        mock_connector = MagicMock()
        mock_conn = MagicMock()
        mock_connector.connect.return_value = mock_conn

        # The code snippet from documentation:
        # Instead of importing from google.cloud.sql.connector, we mock the instance globally
        connector = mock_connector

        def getconn():
            conn = connector.connect(
                os.environ["DB_INSTANCE_NAME"],
                "pg8000",
                user=os.environ["DB_USER"],
                password=os.environ["DB_PASS"],
                db=os.environ["DB_NAME"]
            )
            return conn

        # run the function
        result = getconn()

        # Check results
        mock_connector.connect.assert_called_once_with(
            "project:region:instance",
            "pg8000",
            user="test-user",
            password="test-password",
            db="test-db"
        )
        self.assertEqual(result, mock_conn)

if __name__ == '__main__':
    unittest.main()
