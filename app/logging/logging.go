package logging

import (
	"encoding/json"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

/**
* Global logger
 */
var logger = logrus.New()

var logRequests bool
var skipPaths []string

/**
* Apply the given configuration to the global logger.
**/
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

/**
*  Global access to the singleton logger
**/
func Log() *logrus.Logger {
	return logger
}

/**
* Gin compatible function to enable logger injection into the gin-framework
**/
func GinHandlerFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !logRequests {
			c.Next()
		} else {
			// Start timer
			start := time.Now()
			path := c.Request.URL.Path
			raw := c.Request.URL.RawQuery
			if raw != "" {
				path = path + "?" + raw
			}

			// Process request
			c.Next()

			if contains(skipPaths, path) {
				return
			}

			// Stop timer
			end := time.Now()
			latency := end.Sub(start)
			method := c.Request.Method
			statusCode := c.Writer.Status()
			errorMessage := c.Errors.ByType(gin.ErrorTypePrivate).String()

			if errorMessage != "" {
				Log().Warnf("Request [%s]%s took %d ms - Result: %d - %s", method, path, latency, statusCode, errorMessage)
			} else {
				Log().Infof("Request [%s]%s took %d ms - Result: %d", method, path, latency, statusCode)
			}
		}
	}
}

/**
* Helper method to print objects with json-serialization information in a more human readable way
 */
func PrettyPrintObject(objectInterface interface{}) string {
	jsonBytes, err := json.Marshal(objectInterface)
	if err != nil {
		logger.Debugf("Was not able to pretty print the object: %v", objectInterface)
		return ""
	}
	return string(jsonBytes)
}

// helper method to check if s contains e
func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
