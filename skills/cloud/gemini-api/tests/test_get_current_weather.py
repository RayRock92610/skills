import unittest

def get_current_weather(location: str) -> str:
    """Example method. Returns the current weather.
    Args: location: The city and state, e.g. San Francisco, CA
    """
    if 'boston' in location.lower():
        return "Snowing"
    return "Sunny"

class TestGetCurrentWeather(unittest.TestCase):
    def test_get_current_weather_boston(self):
        self.assertEqual(get_current_weather("Boston"), "Snowing")
        self.assertEqual(get_current_weather("boston, ma"), "Snowing")
        self.assertEqual(get_current_weather("BOSTON"), "Snowing")

    def test_get_current_weather_other(self):
        self.assertEqual(get_current_weather("San Francisco"), "Sunny")
        self.assertEqual(get_current_weather("New York"), "Sunny")
        self.assertEqual(get_current_weather("London"), "Sunny")
        self.assertEqual(get_current_weather(""), "Sunny") # Edge case

if __name__ == '__main__':
    unittest.main()
