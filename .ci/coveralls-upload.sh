#!/usr/bin/env bash

if [ "$ENABLE_COVERAGE" != "true" ]; then
  echo "ENABLE_COVERAGE not true, exiting..."
  exit 0
fi

if [ -n "$COVERALLS_REPO_TOKEN" ]; then
  echo "COVERALLS_REPO_TOKEN set"
else
  echo "COVERALLS_REPO_TOKEN *not* set"
  exit 1
fi

coveralls --build-root=build --gcov-options '\-lp'
exit $?
