import unittest
from unittest.mock import MagicMock

class TestGetConn(unittest.TestCase):
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
                "project:region:instance",
                "pg8000",
                user="my-user",
                password="my-password",
                db="my-db"
            )
            return conn

        # run the function
        result = getconn()

        # Check results
        mock_connector.connect.assert_called_once_with(
            "project:region:instance",
            "pg8000",
            user="my-user",
            password="my-password",
            db="my-db"
        )
        self.assertEqual(result, mock_conn)

if __name__ == '__main__':
    unittest.main()
