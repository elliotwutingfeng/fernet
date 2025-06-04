format:
	dart fix --apply
	dart format .

tests:
	dart pub get
	dart format --output none --set-exit-if-changed .
	dart analyze --fatal-infos
	dart run coverage:test_with_coverage --function-coverage --branch-coverage

tests_with_coverage_report: tests
	rm -rf coverage/html
	genhtml --ignore-errors inconsistent --function-coverage --branch-coverage coverage/lcov.info -o coverage/html
