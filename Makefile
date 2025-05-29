tests:
	dart pub get
	dart format --output none --set-exit-if-changed .
	dart analyze
	dart test --coverage "coverage"
	dart run coverage:test_with_coverage --function-coverage --branch-coverage

tests_with_coverage_report: tests
	genhtml coverage/lcov.info -o coverage/html
