package logging

import (
	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

var logRequests bool
var skipPaths []string

func Log() *logrus.Logger {
	return logger
}

func Configure(jsonLogging bool, logLevel string, logRequestsParam bool, skipPathsParam []string) {
	if logLevel == "DEBUG" {
		logger.SetLevel(logrus.DebugLevel)
	} else if logLevel == "INFO" {
		logger.SetLevel(logrus.InfoLevel)
	} else if logLevel == "WARN" {
		logger.SetLevel(logrus.WarnLevel)
	} else if logLevel == "ERROR" {
		logger.SetLevel(logrus.ErrorLevel)
	}

	if jsonLogging {
		logger.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{})
	}

	logRequests = logRequestsParam
	skipPaths = skipPathsParam
}
