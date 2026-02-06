.PHONY: build test clean coverage coverage-html coverage-summary

build:
	dune build

test:
	dune test

clean:
	dune clean
	rm -rf _coverage

# Run tests with bisect_ppx instrumentation and collect coverage data
coverage:
	rm -rf _coverage
	mkdir -p _coverage
	BISECT_FILE=$$(pwd)/_coverage/bisect dune test --instrument-with bisect_ppx --force

# Print coverage summary to stdout
coverage-summary: coverage
	bisect-ppx-report summary --coverage-path _coverage

# Generate HTML coverage report in _coverage/html/
coverage-html: coverage
	bisect-ppx-report html --coverage-path _coverage -o _coverage/html
	@echo "Coverage report: _coverage/html/index.html"
