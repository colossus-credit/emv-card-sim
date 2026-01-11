#!/bin/bash

# Set Java 17 for this script
export JAVA_HOME=/usr/local/Cellar/openjdk@17/17.0.16/libexec/openjdk.jdk/Contents/Home
export PATH=$JAVA_HOME/bin:$PATH

# Verify Java version
echo "Using Java version:"
java -version

# Stop any existing Gradle daemons
./gradlew --stop

# Clean and run Colossus tests
./gradlew clean test --tests ColossusPaymentApplicationTest

echo "Tests completed!"










