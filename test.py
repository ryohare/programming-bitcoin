from unittest import TestSuite, TextTestRunner
import ecc


def run(test):
    suite = TestSuite()
    suite.addTest(test)
    TextTestRunner().run(suite)

# being tests
run(ecc.FieldElementTest('test_on_curve'))
run(ecc.FieldElementTest('test_add'))


