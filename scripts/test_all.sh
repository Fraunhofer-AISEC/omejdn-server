#!/bin/sh

testfiles="$(ls -1 tests/test_*.rb; ls -1 tests/plugins/test*.rb)"

for file in $testfiles; do
	echo "Testing $file"
	bundle exec ruby "$file" --use-color
	if [ "$?" -ne "0" ]; then
		echo "Error: Test $file unsucessful"
		exit 1
	fi
done

echo "All tests passed."
