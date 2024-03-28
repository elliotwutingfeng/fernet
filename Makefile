tests:
	dart pub get
	dart format --output none --set-exit-if-changed .
	dart analyze
	dart test --coverage "coverage"
	dart run coverage:format_coverage --lcov --check-ignore --in coverage --out coverage.lcov --report-on lib
