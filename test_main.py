import unittest
from main import classify, normalize


class IocTests(unittest.TestCase):
    def test_classification(self):
        self.assertEqual(classify("192.0.2.1")["type"], "ip")
        self.assertEqual(classify("Example.COM.")["normalized"], "example.com")
        self.assertEqual(classify("a" * 64)["type"], "hash-256")

    def test_deduplicates(self):
        self.assertEqual(len(normalize(["example.com", "EXAMPLE.COM"])), 1)


if __name__ == "__main__":
    unittest.main()
